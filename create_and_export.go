package mpcium

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/nats-io/nats.go"
)

// WalletExportOptions is trusted cluster configuration, reused across wallets.
// NodePublicKeys must be provisioned out of band, never learned from NATS replies.
type WalletExportOptions struct {
	KeyType              types.KeyType
	Threshold            int
	Participants         []string
	NodePublicKeys       map[string]ed25519.PublicKey
	AuthorizerSignatures []types.AuthorizerSignature
}

// CreatedWalletExport returns the secret plus public metadata to pin for later
// startup exports. Persist Policy with trusted application config, not PrivateKey.
// If DKG succeeds but export fails, a non-nil result still carries public Policy.
type CreatedWalletExport struct {
	WalletID   string
	Policy     keyexport.Policy
	PrivateKey []byte
}

var newWalletID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// CreateWalletAndExport creates a fresh project wallet, waits for DKG and exports
// it. Projects support export by default, subject to identity and wallet scope checks.
// It uses its own temporary JetStream result consumer and acknowledges results,
// leaving the caller's ordinary result subscriptions unchanged.
// Timeout may mean the wallet was already created: do not assume rollback.
func (c *mpcClient) CreateWalletAndExport(ctx context.Context, walletID string, opts WalletExportOptions) (*CreatedWalletExport, error) {
	if c.projectID == "" || !newWalletID.MatchString(walletID) {
		return nil, errors.New("create-and-export requires a project and valid wallet ID")
	}
	if opts.KeyType == "" {
		opts.KeyType = types.KeyTypeSecp256k1
	}
	if opts.KeyType != types.KeyTypeSecp256k1 && opts.KeyType != types.KeyTypeEd25519 {
		return nil, errors.New("unsupported export key type")
	}
	if opts.Threshold < 2 || opts.Threshold > len(opts.Participants) || len(opts.Participants) > 32 {
		return nil, errors.New("invalid export threshold")
	}
	opts.Participants = append([]string(nil), opts.Participants...)
	pinned := make(map[string]ed25519.PublicKey, len(opts.Participants))
	seen := map[string]bool{}
	for _, id := range opts.Participants {
		if !newWalletID.MatchString(id) || seen[id] || len(opts.NodePublicKeys[id]) != ed25519.PublicKeySize {
			return nil, errors.New("missing or invalid pinned export node")
		}
		seen[id] = true
		pinned[id] = append(ed25519.PublicKey(nil), opts.NodePublicKeys[id]...)
	}
	pub, err := c.signer.PublicKey()
	if err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(pub)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	js, err := c.natsConn.JetStream()
	if err != nil {
		return nil, err
	}
	operationID := "create-export-" + uuid.NewString()
	sub, err := js.PullSubscribe(event.KeygenResultSubject(operationID, walletID), "", nats.BindStream("mpc"), nats.DeliverAll(), nats.AckExplicit(), nats.InactiveThreshold(time.Minute))
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err = c.createWalletWithContext(ctx, walletID, opts.AuthorizerSignatures, operationID); err != nil {
		return nil, fmt.Errorf("create wallet %s (check existence before retry): %w", walletID, err)
	}
	for {
		messages, err := sub.Fetch(1, nats.Context(ctx))
		if err != nil {
			return nil, fmt.Errorf("waiting for wallet %s; it may already exist: %w", walletID, err)
		}
		if len(messages) == 0 {
			continue
		}
		msg := messages[0]
		// Result messages contain public metadata only; acknowledge each received
		// item so this one-shot API does not leave an unconsumed work queue backlog.
		_ = msg.Ack()
		if len(msg.Data) > 64*1024 {
			continue
		}
		var result event.KeygenResultEvent
		if json.Unmarshal(msg.Data, &result) != nil || result.WalletID != walletID {
			continue
		}
		if result.ResultType == event.ResultTypeError {
			return nil, fmt.Errorf("wallet %s creation failed: %s", walletID, result.ErrorCode)
		}
		if result.ResultType != event.ResultTypeSuccess {
			continue
		}
		public := result.ECDSAPubKey
		if opts.KeyType == types.KeyTypeEd25519 {
			public = result.EDDSAPubKey
		} else if len(public) == 64 {
			public = append([]byte{4}, public...)
		}
		public, err = keyexport.ParsePublicKey(opts.KeyType, public)
		if err != nil {
			return nil, fmt.Errorf("wallet %s result public key invalid: %w", walletID, err)
		}
		// Fresh wallets currently start at version 1. Reshared or existing wallets
		// must use ExportPrivateKey with explicitly pinned current metadata.
		policy := keyexport.Policy{ProjectID: c.projectID, WalletID: walletID, KeyType: opts.KeyType, KeyVersion: 1, Threshold: opts.Threshold, Participants: opts.Participants, InitiatorFingerprint: keyexport.Fingerprint(pubBytes), PublicKey: public}
		wallet := &CreatedWalletExport{WalletID: walletID, Policy: policy}
		// Keygen completion can race peers finishing local persistence. Retry
		// only this signed insufficient-response outcome, with fresh requests,
		// bounded backoff and no relaxation of any authorization check.
		for attempt := 0; attempt < 6; attempt++ {
			secret, exportErr := c.ExportPrivateKey(ctx, keyexport.Options{Policy: policy, NodePublicKeys: pinned})
			if exportErr == nil {
				wallet.PrivateKey = secret
				return wallet, nil
			}
			if !errors.Is(exportErr, keyexport.ErrInsufficientNodes) || attempt == 5 {
				return wallet, fmt.Errorf("wallet %s created, export failed: %w", walletID, exportErr)
			}
			timer := time.NewTimer(time.Duration(100*(1<<attempt)) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return wallet, fmt.Errorf("wallet %s created, export incomplete: %w", walletID, ctx.Err())
			case <-timer.C:
			}
		}

	}
}
