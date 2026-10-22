package mpcium

import (
	"context"
	"errors"

	"github.com/jaronnie/mpcium-go/configsecret"
)

// SecretClient is independent of wallet signing/export and uses core NATS only.
type SecretClient struct {
	opts     Options
	manifest configsecret.Manifest
}

func NewSecretClient(opts Options, manifest configsecret.Manifest) (*SecretClient, error) {
	if opts.ProjectID == "" || opts.ProjectID != manifest.ProjectID || opts.NatsConn == nil || opts.Signer == nil {
		return nil, errors.New("config secrets require matching project, connection and signer")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	// Freeze public policy: callers must not be able to mutate it after creation.
	manifest.Nodes = append([]configsecret.Node(nil), manifest.Nodes...)
	for i := range manifest.Nodes {
		manifest.Nodes[i].IdentityKey = append([]byte(nil), manifest.Nodes[i].IdentityKey...)
	}
	manifest.Commitments = append([][]byte(nil), manifest.Commitments...)
	for i := range manifest.Commitments {
		manifest.Commitments[i] = append([]byte(nil), manifest.Commitments[i]...)
	}
	return &SecretClient{opts, manifest}, nil
}
func (c *SecretClient) Decrypt(ctx context.Context, name string, envelope configsecret.Envelope) ([]byte, error) {
	return configsecret.Decrypt(ctx, c.opts.NatsConn, c.opts.Signer, envelope, configsecret.DecryptOptions{Manifest: c.manifest, Name: name})
}

// Encrypt uses the same pinned policy as Decrypt. It returns ciphertext for the
// caller to store and does not mutate the server's saved data.
func (c *SecretClient) Encrypt(name string, plaintext []byte) (configsecret.Envelope, error) {
	return configsecret.Encrypt(c.manifest, name, plaintext)
}
