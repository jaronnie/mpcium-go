package mpcium

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/logger"
	"github.com/jaronnie/mpcium-go/messaging"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/nats-io/nats.go"
)

type MPCClient interface {
	EncryptData(context.Context, string, []byte) ([]byte, error)
	DecryptData(context.Context, string, []byte) ([]byte, error)
	DecryptStoredData(context.Context, string) ([]byte, error)
	ExportWallet(context.Context, string, ...types.KeyType) ([]byte, error)
	ExportSolanaKeypair(context.Context, string) ([]byte, error)
	// ExportPrivateKey is synchronous and returns raw secret bytes, never a remote signer.
	ExportPrivateKey(context.Context, keyexport.Options) ([]byte, error)
	CreateWalletAndExport(context.Context, string, WalletExportOptions) (*CreatedWalletExport, error)
	CreateWallet(walletID string) error
	CreateWalletWithAuthorizers(walletID string, authorizerSignatures []types.AuthorizerSignature) error
	OnWalletCreationResult(callback func(event event.KeygenResultEvent)) error

	SignTransaction(msg *types.SignTxMessage) error
	OnSignResult(callback func(event event.SigningResultEvent)) error

	Resharing(msg *types.ResharingMessage) error
	OnResharingResult(callback func(event event.ResharingResultEvent)) error
}

type mpcClient struct {
	accessSession       string
	nodePublicKeys      map[string]ed25519.PublicKey
	projectID           string
	natsConn            *nats.Conn
	signingBroker       messaging.MessageBroker
	keygenBroker        messaging.MessageBroker
	pubsub              messaging.PubSub
	genKeySuccessQueue  messaging.MessageQueue
	signResultQueue     messaging.MessageQueue
	reshareSuccessQueue messaging.MessageQueue
	signer              Signer
	clientID            string
}

// Options defines configuration options for creating a new MPCClient
type Options struct {
	// Node trust is loaded from the encrypted credentials by Connect; applications
	// do not maintain cluster settings. Legacy signing clients may omit it.
	NodePublicKeys map[string]ed25519.PublicKey
	// ProjectID selects the node-configured project identity and wallet scope.
	ProjectID string
	// NATS connection
	NatsConn *nats.Conn

	// Signer for signing messages
	Signer Signer

	// ClientID optionally scopes result routing for this client instance.
	ClientID string
}

type clientResultRouting struct {
	keygenConsumerName  string
	keygenSubject       string
	signingConsumerName string
	signingSubject      string
	reshareConsumerName string
	reshareSubject      string
}

// NewMPCClient creates a new MPC client using the provided options.
// The signer must be provided to handle message signing.
func NewMPCClient(opts Options) MPCClient {
	if opts.Signer == nil {
		logger.Fatal("Signer is required", nil)
	}
	if err := validateClientID(opts.ClientID); err != nil {
		logger.Fatal("Invalid client ID", err)
	}

	// 2) Create the PubSub for both publish & subscribe
	signingBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		"mpc-signing",
		[]string{
			"mpc.signing_request.*",
		},
	)
	if err != nil {
		logger.Fatal("Failed to create signing jetstream broker", err)
	}
	keygenBroker, err := messaging.NewJetStreamBroker(
		context.Background(),
		opts.NatsConn,
		"mpc-keygen",
		[]string{
			"mpc.keygen_request.*",
		},
	)
	if err != nil {
		logger.Fatal("Failed to create keygen jetstream broker", err)
	}

	pubsub := messaging.NewNATSPubSub(opts.NatsConn)

	manager := messaging.NewNATsMessageQueueManager("mpc", event.ResultStreamSubjects(), opts.NatsConn)
	routing := buildClientResultRouting(opts.ClientID)

	genKeySuccessQueue := manager.NewMessageQueue(routing.keygenConsumerName, routing.keygenSubject)
	signResultQueue := manager.NewMessageQueue(routing.signingConsumerName, routing.signingSubject)
	reshareSuccessQueue := manager.NewMessageQueue(routing.reshareConsumerName, routing.reshareSubject)

	return &mpcClient{
		nodePublicKeys:      cloneSDKNodes(opts.NodePublicKeys),
		natsConn:            opts.NatsConn,
		projectID:           opts.ProjectID,
		signingBroker:       signingBroker,
		keygenBroker:        keygenBroker,
		pubsub:              pubsub,
		genKeySuccessQueue:  genKeySuccessQueue,
		signResultQueue:     signResultQueue,
		reshareSuccessQueue: reshareSuccessQueue,
		signer:              opts.Signer,
		clientID:            opts.ClientID,
	}
}

// CreateWallet generates a GenerateKeyMessage, signs it, and publishes it.
func (c *mpcClient) CreateWallet(walletID string) error {
	return c.CreateWalletWithAuthorizers(walletID, nil)
}

// CreateWalletWithAuthorizers generates a GenerateKeyMessage with authorizer signatures, signs it, and publishes it.
func (c *mpcClient) CreateWalletWithAuthorizers(walletID string, authorizerSignatures []types.AuthorizerSignature) error {
	return c.createWalletWithContext(context.Background(), walletID, authorizerSignatures, c.clientID)
}

func (c *mpcClient) createWalletWithContext(ctx context.Context, walletID string, authorizerSignatures []types.AuthorizerSignature, resultClientID string) error {
	// build the message
	msg := &types.GenerateKeyMessage{
		WalletID:             walletID,
		ProjectID:            c.projectID,
		AuthorizerSignatures: authorizerSignatures,
	}
	// compute the canonical raw bytes
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("CreateWallet: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("CreateWallet: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("CreateWallet: marshal error: %w", err)
	}

	var headers map[string]string
	if resultClientID != "" {
		headers = map[string]string{event.ClientIDHeader: resultClientID}
	}
	if err := c.keygenBroker.PublishMessage(ctx, event.KeygenRequestTopic, bytes, headers); err != nil {
		return fmt.Errorf("CreateWallet: publish error: %w", err)
	}
	return nil
}

// The callback will be invoked whenever a wallet creation result is received.
func (c *mpcClient) OnWalletCreationResult(callback func(event event.KeygenResultEvent)) error {
	err := c.genKeySuccessQueue.Dequeue(event.KeygenResultSubscriptionSubject(c.clientID), func(msg []byte) error {
		var event event.KeygenResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnWalletCreationResult: subscribe error: %w", err)
	}

	return nil
}

// SignTransaction builds a SignTxMessage, signs it, and publishes it.
func (c *mpcClient) SignTransaction(msg *types.SignTxMessage) error {
	if msg == nil {
		return fmt.Errorf("nil signing request")
	}
	if err := bindProject(c.projectID, &msg.ProjectID); err != nil {
		return err
	}
	// compute the canonical raw bytes (omitting Signature field)
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("SignTransaction: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("SignTransaction: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("SignTransaction: marshal error: %w", err)
	}

	if err := c.signingBroker.PublishMessage(context.Background(), event.SigningRequestTopic, bytes, c.requestHeaders()); err != nil {
		return fmt.Errorf("SignTransaction: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnSignResult(callback func(event event.SigningResultEvent)) error {
	err := c.signResultQueue.Dequeue(event.SigningResultSubscriptionSubject(c.clientID), func(msg []byte) error {
		var event event.SigningResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			return err
		}
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnSignResult: subscribe error: %w", err)
	}

	return nil
}

func (c *mpcClient) Resharing(msg *types.ResharingMessage) error {
	if msg == nil {
		return fmt.Errorf("nil resharing request")
	}
	if err := bindProject(c.projectID, &msg.ProjectID); err != nil {
		return err
	}
	// compute the canonical raw bytes
	raw, err := msg.Raw()
	if err != nil {
		return fmt.Errorf("Resharing: raw payload error: %w", err)
	}
	signature, err := c.signer.Sign(raw)
	if err != nil {
		return fmt.Errorf("Resharing: failed to sign message: %w", err)
	}
	msg.Signature = signature

	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Resharing: marshal error: %w", err)
	}

	if err := c.pubsub.Publish("mpc:reshare", bytes, c.requestHeaders()); err != nil {
		return fmt.Errorf("Resharing: publish error: %w", err)
	}
	return nil
}

func (c *mpcClient) OnResharingResult(callback func(event event.ResharingResultEvent)) error {
	err := c.reshareSuccessQueue.Dequeue(event.ReshareResultSubscriptionSubject(c.clientID), func(msg []byte) error {
		logger.Info("Received reshare success message", "raw", string(msg))
		var event event.ResharingResultEvent
		err := json.Unmarshal(msg, &event)
		if err != nil {
			logger.Error("Failed to unmarshal reshare success event", err, "raw", string(msg))
			return err
		}
		logger.Info("Deserialized reshare success event", "event", event)
		callback(event)
		return nil
	})

	if err != nil {
		return fmt.Errorf("OnResharingResult: subscribe error: %w", err)
	}

	return nil
}

func (c *mpcClient) requestHeaders() map[string]string {
	if c.clientID == "" {
		return nil
	}
	return map[string]string{
		event.ClientIDHeader: c.clientID,
	}
}

func buildClientResultRouting(clientID string) clientResultRouting {
	return clientResultRouting{
		keygenConsumerName:  event.ResultConsumerName("mpc_keygen_result", clientID),
		keygenSubject:       event.KeygenResultSubscriptionSubject(clientID),
		signingConsumerName: event.ResultConsumerName("mpc_signing_result", clientID),
		signingSubject:      event.SigningResultSubscriptionSubject(clientID),
		reshareConsumerName: event.ResultConsumerName("mpc_reshare_result", clientID),
		reshareSubject:      event.ReshareResultSubscriptionSubject(clientID),
	}
}

func validateClientID(clientID string) error {
	if clientID == "" {
		return nil
	}
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("client ID cannot be blank")
	}
	if strings.ContainsAny(clientID, " \t\r\n.*>") {
		return fmt.Errorf("client ID must be a single NATS subject token")
	}
	return nil
}

func (c *mpcClient) ExportPrivateKey(ctx context.Context, opts keyexport.Options) ([]byte, error) {
	if err := bindProject(c.projectID, &opts.Policy.ProjectID); err != nil {
		return nil, err
	}
	return keyexport.ExportPrivateKey(ctx, c.natsConn, c.signer, opts)
}

func bindProject(configured string, supplied *string) error {
	if *supplied != "" && *supplied != configured {
		return fmt.Errorf("request project differs from client project")
	}
	*supplied = configured
	return nil
}
