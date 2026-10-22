package mpcium

import (
	"context"
	"errors"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/nats-io/nats.go"
)

// ExportClient uses core NATS only, without creating JetStream consumers.
// The caller owns the connection and closes it after startup export.
type ExportClient struct {
	projectID string
	conn      *nats.Conn
	signer    Signer
}

func NewExportClient(opts Options) (*ExportClient, error) {
	if opts.NatsConn == nil || opts.Signer == nil {
		return nil, errors.New("export requires connection and initiator signer")
	}
	return &ExportClient{conn: opts.NatsConn, signer: opts.Signer, projectID: opts.ProjectID}, nil
}
func (c *ExportClient) ExportPrivateKey(ctx context.Context, opts keyexport.Options) ([]byte, error) {
	if err := bindProject(c.projectID, &opts.Policy.ProjectID); err != nil {
		return nil, err
	}
	return keyexport.ExportPrivateKey(ctx, c.conn, c.signer, opts)
}
