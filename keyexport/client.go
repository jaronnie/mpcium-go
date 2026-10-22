package keyexport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

var ErrInsufficientNodes = errors.New("insufficient nodes authorized or able to export")

type Signer interface {
	Sign([]byte) ([]byte, error)
	PublicKey() (string, error)
}

// Options must be pinned in trusted business configuration, not read from an
// unauthenticated Consul/NATS reply. NodePublicKeys maps node IDs to Ed25519 keys.
type Options struct {
	Policy         Policy
	NodePublicKeys map[string]ed25519.PublicKey
}

// ExportPrivateKey returns a 32-byte BIG-ENDIAN scalar. For secp256k1 this is
// an ordinary EVM private key. For Ed25519 it is NOT a seed or Solana keypair.
// The caller owns the returned secret and the NATS connection's lifetime.
func ExportPrivateKey(ctx context.Context, nc *nats.Conn, signer Signer, opts Options) ([]byte, error) {
	if nc == nil || signer == nil {
		return nil, errors.New("export requires connection and initiator")
	}
	if err := opts.Policy.Validate(); err != nil {
		return nil, err
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(pub)
	if err != nil || Fingerprint(pubBytes) != opts.Policy.InitiatorFingerprint {
		return nil, errors.New("initiator differs from export policy")
	}
	members := map[string]bool{}
	for _, id := range opts.Policy.Participants {
		members[id] = true
		if len(opts.NodePublicKeys[id]) != ed25519.PublicKeySize {
			return nil, errors.New("missing pinned node public key")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, MaxLifetime-5*time.Second)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	// No secrets are published before subscribing; each call owns a fresh inbox.
	inbox := "_INBOX." + uuid.NewString() + "." + uuid.NewString()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err = sub.SetPendingLimits(128, maxMessage*128); err != nil {
		return nil, err
	}
	if err = nc.FlushWithContext(ctx); err != nil {
		return nil, err
	}
	now := time.Now()
	request := Request{Domain: Domain, RequestID: uuid.NewString(), Policy: opts.Policy, Recipient: identity.Recipient().String(), Reply: inbox, IssuedAt: now.Unix(), ExpiresAt: now.Add(MaxLifetime - 5*time.Second).Unix()}
	raw, _ := request.Raw()
	request.Signature, err = signer.Sign(raw)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	for _, id := range opts.Policy.Participants {
		if err = nc.Publish(Subject(id), body); err != nil {
			return nil, err
		}
	}
	if err = nc.FlushWithContext(ctx); err != nil {
		return nil, err
	}
	shares := recoveryShares{}
	seen := map[string]bool{}
	ids := map[string]bool{}
	responded := map[string]bool{}
	defer func() {
		for _, s := range shares {
			s.Share.SetInt64(0)
		}
	}()
	digest := request.Digest()
	curve := Curve(opts.Policy.KeyType)
	for len(shares) < opts.Policy.Threshold {
		msg, e := sub.NextMsgWithContext(ctx)
		if e != nil {
			return nil, fmt.Errorf("export received %d/%d valid shares: %w", len(shares), opts.Policy.Threshold, e)
		}
		if len(msg.Data) > maxMessage {
			continue
		}
		var response Response
		if json.Unmarshal(msg.Data, &response) != nil || response.Domain != Domain || !members[response.NodeID] || response.RequestDigest != digest || len(opts.NodePublicKeys[response.NodeID]) != ed25519.PublicKeySize || !ed25519.Verify(opts.NodePublicKeys[response.NodeID], response.Raw(), response.Signature) {
			continue
		}
		if responded[response.NodeID] {
			continue
		}
		responded[response.NodeID] = true
		if response.Error == "" {
			share, e := decryptShare(identity, response.Ciphertext)
			if e == nil {
				id := new(big.Int).SetBytes(share.ID)
				id.Mod(id, curve.Params().N)
				expectedID := new(big.Int).SetBytes([]byte(response.NodeID + ":" + strconv.Itoa(opts.Policy.KeyVersion)))
				expectedID.Mod(expectedID, curve.Params().N)
				value := new(big.Int).SetBytes(share.Value)
				clear(share.Value)
				if share.RequestDigest == digest && share.NodeID == response.NodeID && bytes.Equal(share.PublicKey, opts.Policy.PublicKey) && !seen[share.NodeID] && !ids[id.String()] && id.Cmp(expectedID) == 0 && id.Sign() > 0 && id.Cmp(curve.Params().N) < 0 && value.Sign() > 0 && value.Cmp(curve.Params().N) < 0 {
					seen[share.NodeID] = true
					ids[id.String()] = true
					shares = append(shares, &recoveryShare{Threshold: opts.Policy.Threshold - 1, ID: id, Share: value})
				} else {
					value.SetInt64(0)
				}
			}
		}
		if len(shares)+len(opts.Policy.Participants)-len(responded) < opts.Policy.Threshold {
			return nil, ErrInsufficientNodes
		}
	}
	scalar, err := shares.ReConstruct(curve)
	if err != nil {
		return nil, err
	}
	defer scalar.SetInt64(0)
	if scalar.Sign() <= 0 || !bytes.Equal(PublicKey(opts.Policy.KeyType, scalar), opts.Policy.PublicKey) {
		return nil, errors.New("reconstructed key does not match pinned public key")
	}
	return scalar.FillBytes(make([]byte, 32)), nil
}
func decryptShare(identity *age.X25519Identity, ciphertext []byte) (*Share, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > maxMessage {
		return nil, errors.New("share too large")
	}
	var share Share
	if err = json.Unmarshal(plain, &share); err != nil {
		return nil, err
	}
	if len(share.ID) > 256 || len(share.Value) > 32 {
		return nil, errors.New("invalid scalar length")
	}
	return &share, nil
}
