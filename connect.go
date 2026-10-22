package mpcium

import (
	"context"
	"crypto/tls"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Connect returns the existing Options type for use by all SDK clients.
// The caller owns both the returned connection and the supplied credentials.
func Connect(ctx context.Context, address, token, projectID string, credentials *Credentials) (Options, error) {
	if err := ctx.Err(); err != nil {
		return Options{}, err
	}
	if credentials == nil || credentials.Initiator == nil || projectID == "" || credentials.ProjectID != projectID {
		return Options{}, errors.New("project ID must match unlocked credentials")
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || token == "" {
		return Options{}, errors.New("TLS NATS URL and token are required")
	}
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	clientID := "sdk-" + uuid.NewString()
	nc, err := nats.Connect(address, nats.Name(clientID), nats.Token(token), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12}), nats.Timeout(timeout))
	if err != nil {
		return Options{}, err
	}
	if err := ctx.Err(); err != nil {
		nc.Close()
		return Options{}, err
	}
	return Options{ClientID: clientID, NodePublicKeys: cloneSDKNodes(credentials.NodePublicKeys), ProjectID: projectID, NatsConn: nc, Signer: credentials.Initiator}, nil
}
