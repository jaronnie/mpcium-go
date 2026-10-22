package mpcium

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/nats-io/nats.go"
)

// AccessClient connects only to the public, restricted NATS account. It never
// creates JetStream consumers or publishes directly on internal MPC subjects.
type AccessClient struct {
	client  *mpcClient
	session string
}

func ConnectAccess(ctx context.Context, address string, credentials *Credentials, options ...nats.Option) (*AccessClient, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if credentials == nil || credentials.Initiator == nil || !newWalletID.MatchString(credentials.ProjectID) || credentials.AccessToken == "" {
		return nil, errors.New("project credentials with embedded access token required")
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("TLS NATS URL required")
	}
	if err = validateSDKNodes(credentials.NodePublicKeys); err != nil {
		return nil, err
	}
	session := "access-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	opts := append([]nats.Option{nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12})}, options...)
	opts = append(opts, nats.Name(session), nats.Token(credentials.AccessToken), nats.CustomInboxPrefix("_INBOX."+session), nats.Timeout(timeout))
	nc, err := nats.Connect(address, opts...)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		nc.Close()
		return nil, err
	}
	c := &mpcClient{natsConn: nc, projectID: credentials.ProjectID, signer: credentials.Initiator, nodePublicKeys: cloneSDKNodes(credentials.NodePublicKeys), accessSession: session}
	return &AccessClient{client: c, session: session}, nil
}
func (c *AccessClient) Close() { c.client.natsConn.Close() }
func (c *AccessClient) CreateWallet(ctx context.Context, id string) (event.KeygenResultEvent, error) {
	var result event.KeygenResultEvent
	request := types.GenerateKeyMessage{ProjectID: c.client.projectID, WalletID: id}
	raw, err := request.Raw()
	if err != nil {
		return result, err
	}
	request.Signature, err = c.client.signer.Sign(raw)
	if err != nil {
		return result, err
	}
	data, err := c.call(ctx, "wallet", id, "keygen", "cluster", request)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.WalletID != id || result.ResultType != event.ResultTypeSuccess {
		return result, errors.New("wallet creation unsuccessful; check wallet state before retry")
	}
	return result, nil
}
func (c *AccessClient) SignTransaction(ctx context.Context, request *types.SignTxMessage) (event.SigningResultEvent, error) {
	var result event.SigningResultEvent
	if request == nil {
		return result, errors.New("nil signing request")
	}
	copy := *request
	if err := bindProject(c.client.projectID, &copy.ProjectID); err != nil {
		return result, err
	}
	raw, err := copy.Raw()
	if err != nil {
		return result, err
	}
	copy.Signature, err = c.client.signer.Sign(raw)
	if err != nil {
		return result, err
	}
	data, err := c.call(ctx, "wallet", copy.WalletID, "sign", "cluster", copy)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.WalletID != copy.WalletID || result.TxID != copy.TxID || result.ResultType != event.ResultTypeSuccess {
		return result, errors.New("wallet signing unsuccessful")
	}
	// Signature verification against the wallet's pinned public key remains the
	// caller's responsibility, as with the existing OnSignResult API.
	return result, nil
}
func (c *AccessClient) EncryptData(ctx context.Context, id string, b []byte) ([]byte, error) {
	return c.client.EncryptData(ctx, id, b)
}
func (c *AccessClient) DecryptData(ctx context.Context, id string, b []byte) ([]byte, error) {
	return c.client.DecryptData(ctx, id, b)
}
func (c *AccessClient) DecryptStoredData(ctx context.Context, id string) ([]byte, error) {
	return c.client.DecryptStoredData(ctx, id)
}
func (c *AccessClient) ExportWallet(ctx context.Context, id string) ([]byte, error) {
	return c.client.ExportWallet(ctx, id)
}
func (c *AccessClient) call(ctx context.Context, kind, id, operation, node string, v any) ([]byte, error) {
	if !newWalletID.MatchString(id) || !newWalletID.MatchString(node) {
		return nil, errors.New("invalid access route")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	subject := accessSubject(c.session, c.client.projectID, kind, id, operation, node)
	message, err := c.client.natsConn.RequestWithContext(ctx, subject, raw)
	if err != nil {
		return nil, fmt.Errorf("access request failed (operation may already have started): %w", err)
	}
	return unwrapAccess(message.Data)
}
func accessSubject(session, project, kind, id, operation, node string) string {
	return strings.Join([]string{"access", "v1", session, project, kind, id, operation, node}, ".")
}
func unwrapAccess(b []byte) ([]byte, error) {
	if len(b) > 256*1024 {
		return nil, errors.New("oversized access response")
	}
	var r struct {
		Error string `json:"access_error"`
		Data  []byte `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, errors.New("access request denied or unavailable")
	}
	if len(r.Data) == 0 {
		return nil, errors.New("empty access response")
	}
	return r.Data, nil
}
