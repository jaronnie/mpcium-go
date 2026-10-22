package configsecret

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"filippo.io/age"
	"github.com/jaronnie/mpcium-go/types"
)

const maxMessage = 64 * 1024

var inboxPattern = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func Subject(nodeID string) string { return "mpc.config_secret.v1." + nodeID }

type Request struct {
	Domain    string   `json:"domain"`
	RequestID string   `json:"request_id"`
	Envelope  Envelope `json:"envelope"`
	Recipient string   `json:"recipient"`
	Reply     string   `json:"reply"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
	Signature []byte   `json:"signature,omitempty"`
}

func (r *Request) Raw() ([]byte, error) {
	c := *r
	c.Signature = nil
	return json.Marshal(c)
}
func (r *Request) Sig() []byte                                          { return r.Signature }
func (r *Request) InitiatorID() string                                  { return r.Envelope.ProjectID }
func (r *Request) GetAuthorizerSignatures() []types.AuthorizerSignature { return nil }
func (r *Request) GetProjectID() string                                 { return r.Envelope.ProjectID }

// Config secrets intentionally have no wallet ID or namespace.
func (r *Request) GetWalletID() string    { return "" }
func (r *Request) GetSecretKeyID() string { return r.Envelope.KeyID }
func (r *Request) GetOperation() string   { return "decrypt" }
func (r *Request) Digest() string {
	b, _ := r.Raw()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (r *Request) Validate(now time.Time) error {
	if r.Domain != Domain || !identifier.MatchString(r.RequestID) || !projectIdentifier.MatchString(r.Envelope.ProjectID) || !identifier.MatchString(r.Envelope.KeyID) || !inboxPattern.MatchString(r.Reply) || r.IssuedAt > now.Unix()+5 || r.ExpiresAt <= now.Unix() || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > 60 {
		return errors.New("invalid config decrypt request")
	}
	_, err := age.ParseX25519Recipient(r.Recipient)
	return err
}

type Response struct {
	Domain     string `json:"domain"`
	Digest     string `json:"digest"`
	NodeID     string `json:"node_id"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Error      string `json:"error,omitempty"`
	Signature  []byte `json:"signature,omitempty"`
}

func (r Response) Raw() []byte { r.Signature = nil; b, _ := json.Marshal(r); return b }
