package mpcium

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/nats-io/nats.go"
	"net/url"
	"time"
)

func validateTransport(b CredentialsBundle) error {
	u, e := url.Parse(b.NATSURL)
	if e != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || b.ProjectID == "" || b.NATSUsername == "" || b.NATSPassword == "" || b.NATSToken != "" {
		return errors.New("invalid project NATS transport")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.NATSCA) {
		return errors.New("invalid NATS CA")
	}
	if _, e = tls.X509KeyPair(b.NATSClientCert, b.NATSClientKey); e != nil {
		return errors.New("invalid NATS client certificate")
	}
	return nil
}

// ConnectNATS connects using a v2 project's bundled username/password, trusted CA
// and mTLS client identity. V1 callers can keep their existing nats.Token setup.
func (c *Credentials) ConnectNATS(ctx context.Context) (*nats.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Initiator == nil || c.ProjectID == "" || c.NATSURL == "" {
		return nil, errors.New("project transport is not included; use the legacy connection setup for v1 bundles")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.NATSCA) {
		return nil, errors.New("invalid NATS CA")
	}
	cert, err := tls.X509KeyPair(c.NATSClientCert, c.NATSClientKey)
	if err != nil {
		return nil, err
	}
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	return nats.Connect(c.NATSURL, nats.Name("sdk-"+c.ProjectID), nats.UserInfo(c.NATSUsername, c.NATSPassword), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}), nats.Timeout(timeout))
}
