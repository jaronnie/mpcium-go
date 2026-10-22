// Package keyexport implements authenticated wallet secret export.
// Export turns a threshold wallet into a locally controlled wallet. It is not
// part of transaction signing; each node verifies project authorization.
package keyexport

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/jaronnie/mpcium-go/types"
)

const Domain = "mpcium/wallet-secret-export/v1"
const MaxLifetime = time.Minute
const maxMessage = 64 * 1024

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// Policy binds wallet metadata to an export request. Exact policies are pinned
// locally; project-wide authorization still validates metadata against local shares.
// Threshold is the minimum number of shares (2 means 2-of-N).
type Policy struct {
	ProjectID            string        `json:"project_id,omitempty" mapstructure:"project_id"`
	WalletID             string        `json:"wallet_id" mapstructure:"wallet_id"`
	KeyType              types.KeyType `json:"key_type" mapstructure:"key_type"`
	KeyVersion           int           `json:"key_version" mapstructure:"key_version"`
	Threshold            int           `json:"threshold" mapstructure:"threshold"`
	Participants         []string      `json:"participants" mapstructure:"participants"`
	InitiatorFingerprint string        `json:"initiator_fingerprint" mapstructure:"initiator_fingerprint"`
	PublicKey            []byte        `json:"public_key" mapstructure:"-"`
}

// Request's signature binds every exported field except Signature itself.
type Request struct {
	Domain    string `json:"domain"`
	RequestID string `json:"request_id"`
	Policy    Policy `json:"policy"`
	Recipient string `json:"recipient"`
	Reply     string `json:"reply"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Signature []byte `json:"signature,omitempty"`
}

func (r *Request) Raw() ([]byte, error) {
	c := *r
	c.Signature = nil
	return json.Marshal(c)
}
func (r *Request) Sig() []byte                                          { return r.Signature }
func (r *Request) InitiatorID() string                                  { return r.RequestID }
func (r *Request) GetAuthorizerSignatures() []types.AuthorizerSignature { return nil }
func (r *Request) Digest() string {
	b, _ := r.Raw()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Fingerprint(publicKey []byte) string {
	h := sha256.Sum256(publicKey)
	return hex.EncodeToString(h[:])
}
func Subject(nodeID string) string { return "mpc.key_export.v1." + nodeID }

func (p Policy) Validate() error {
	if !identifier.MatchString(p.WalletID) || p.KeyVersion < 1 || p.Threshold < 2 || p.Threshold > len(p.Participants) || len(p.Participants) > 32 {
		return errors.New("invalid export wallet, version or threshold")
	}
	if p.KeyType != types.KeyTypeSecp256k1 && p.KeyType != types.KeyTypeEd25519 {
		return errors.New("unsupported export algorithm")
	}
	seen := map[string]bool{}
	for _, id := range p.Participants {
		if !identifier.MatchString(id) || seen[id] {
			return errors.New("invalid or duplicate participant")
		}
		seen[id] = true
	}
	fp, err := hex.DecodeString(p.InitiatorFingerprint)
	if err != nil || len(fp) != 32 {
		return errors.New("invalid initiator fingerprint")
	}
	_, err = ParsePublicKey(p.KeyType, p.PublicKey)
	return err
}
func (r *Request) Validate(now time.Time) error {
	if r.Domain != Domain || !identifier.MatchString(r.RequestID) {
		return errors.New("invalid export domain or request ID")
	}
	if err := r.Policy.Validate(); err != nil {
		return err
	}
	if r.IssuedAt > now.Unix()+5 || r.ExpiresAt <= now.Unix() || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > int64(MaxLifetime/time.Second) {
		return errors.New("invalid export lifetime")
	}
	if !regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`).MatchString(r.Reply) {
		return errors.New("invalid export reply inbox")
	}
	return nil
}

// Share contains only recovery material, never auxiliary Paillier secrets.
type Share struct {
	RequestDigest string `json:"request_digest"`
	NodeID        string `json:"node_id"`
	ID            []byte `json:"id"`
	Value         []byte `json:"value"`
	PublicKey     []byte `json:"public_key"`
}
type Response struct {
	Domain        string `json:"domain"`
	RequestDigest string `json:"request_digest"`
	NodeID        string `json:"node_id"`
	Ciphertext    []byte `json:"ciphertext,omitempty"`
	Error         string `json:"error,omitempty"`
	Signature     []byte `json:"signature,omitempty"`
}

func (r Response) Raw() []byte { r.Signature = nil; b, _ := json.Marshal(r); return b }
func Curve(keyType types.KeyType) elliptic.Curve {
	if keyType == types.KeyTypeEd25519 {
		return edwards.Edwards()
	}
	return btcec.S256()
}
func ParsePublicKey(keyType types.KeyType, b []byte) ([]byte, error) {
	switch keyType {
	case types.KeyTypeSecp256k1:
		x, y := elliptic.Unmarshal(btcec.S256(), b)
		if x == nil {
			return nil, errors.New("expected uncompressed 65-byte secp256k1 public key")
		}
		return elliptic.Marshal(btcec.S256(), x, y), nil
	case types.KeyTypeEd25519:
		p, err := edwards.ParsePubKey(b)
		if err != nil {
			return nil, err
		}
		return p.Serialize(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", keyType)
	}
}
func PublicKey(keyType types.KeyType, scalar *big.Int) []byte {
	x, y := Curve(keyType).ScalarBaseMult(scalar.Bytes())
	if keyType == types.KeyTypeEd25519 {
		return edwards.NewPublicKey(x, y).Serialize()
	}
	return elliptic.Marshal(btcec.S256(), x, y)
}

func (r *Request) GetProjectID() string { return r.Policy.ProjectID }
func (r *Request) GetWalletID() string  { return r.Policy.WalletID }
func (r *Request) GetOperation() string { return "export" }
