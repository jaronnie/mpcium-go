// Package sdkapi carries signed business requests directly to MPC nodes.
// Secret replies are encrypted to a fresh recipient owned only by the caller.
package sdkapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"filippo.io/age"
	"github.com/jaronnie/mpcium-go/configsecret"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/types"
)

const Domain = "mpcium/sdk-business/v1"
const MaxMessage = 96 * 1024
const DataLimit = 16 * 1024

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var inbox = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_.-]{1,200}$`)

func Subject(nodeID string) string { return "mpc.sdk.business.v1." + nodeID }

// Requests contain resource IDs and ciphertext, never data plaintext or private keys.
type Request struct {
	Domain     string `json:"domain"`
	ProjectID  string `json:"project_id"`
	RequestID  string `json:"request_id"`
	Operation  string `json:"operation"`
	ResourceID string `json:"resource_id"`
	Data       []byte `json:"data,omitempty"`
	Recipient  string `json:"recipient"`
	Reply      string `json:"reply"`
	ExpiresAt  int64  `json:"expires_at"`
	Signature  []byte `json:"signature,omitempty"`
}

func (r *Request) Raw() ([]byte, error)                                 { c := *r; c.Signature = nil; return json.Marshal(c) }
func (r *Request) Sig() []byte                                          { return r.Signature }
func (r *Request) InitiatorID() string                                  { return r.ProjectID }
func (r *Request) GetAuthorizerSignatures() []types.AuthorizerSignature { return nil }
func (r *Request) GetProjectID() string                                 { return r.ProjectID }
func (r *Request) GetWalletID() string {
	if r.Operation == "export-wallet" {
		return r.ResourceID
	}
	return ""
}
func (r *Request) GetOperation() string {
	if r.Operation == "export-wallet" {
		return "export"
	}
	return "decrypt"
}
func (r *Request) Digest() string {
	b, _ := r.Raw()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SecretRequest deliberately wraps only data operations: wallet exports must
// pass wallet namespace checks rather than the SecretMessage permission path.
type SecretRequest struct{ *Request }

func (r SecretRequest) GetSecretKeyID() string { return r.ResourceID }
func (r *Request) Validate(now time.Time) error {
	if r.Domain != Domain || !identifier.MatchString(r.ProjectID) || !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.ResourceID) || !inbox.MatchString(r.Reply) || r.ExpiresAt <= now.Unix() || r.ExpiresAt > now.Add(time.Minute).Unix() || len(r.Data) > 48*1024 {
		return errors.New("invalid SDK request")
	}
	switch r.Operation {
	case "encryption-key", "decrypt", "decrypt-stored", "export-wallet":
	default:
		return errors.New("unknown SDK operation")
	}
	if r.Operation != "decrypt" && len(r.Data) != 0 {
		return errors.New("unexpected SDK payload")
	}
	if r.Operation == "decrypt" && len(r.Data) == 0 {
		return errors.New("ciphertext required")
	}
	_, err := age.ParseX25519Recipient(r.Recipient)
	return err
}

type Response struct {
	Domain     string `json:"domain"`
	Digest     string `json:"digest"`
	NodeID     string `json:"node_id"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature,omitempty"`
}

func (r Response) Raw() []byte { r.Signature = nil; b, _ := json.Marshal(r); return b }
func (r Response) Verify(node string, key ed25519.PublicKey, digest string) bool {
	return r.Domain == Domain && r.NodeID == node && r.Digest == digest && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, r.Raw(), r.Signature)
}

// Result is internal proof/recovery material, never application configuration.
// Independently authenticated nodes must agree on the policy before combination.
type Result struct {
	Manifest *configsecret.Manifest `json:"manifest,omitempty"`
	Envelope *configsecret.Envelope `json:"envelope,omitempty"`
	Partial  *configsecret.Partial  `json:"partial,omitempty"`
	Policy   *keyexport.Policy      `json:"policy,omitempty"`
	Share    *keyexport.Share       `json:"share,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

func Encrypt(recipient string, v Result) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(raw); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func Decrypt(identity *age.X25519Identity, b []byte) (Result, error) {
	var result Result
	if len(b) > MaxMessage {
		return result, errors.New("oversized SDK response")
	}
	reader, err := age.Decrypt(bytes.NewReader(b), identity)
	if err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxMessage+1))
	if err != nil {
		return result, err
	}
	defer clear(raw)
	if len(raw) > MaxMessage {
		return result, errors.New("oversized SDK response")
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}
