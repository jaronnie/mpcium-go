package configsecret

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.dedis.ch/kyber/v4/share"
)

type Signer interface{ Sign([]byte) ([]byte, error) }
type DecryptOptions struct {
	Manifest Manifest
	Name     string
}

// Decrypt returns config plaintext, never a long-lived key or scalar share.
// Expected Name and Manifest must come from trusted business configuration.
func Decrypt(ctx context.Context, nc *nats.Conn, signer Signer, e Envelope, opts DecryptOptions) ([]byte, error) {
	m := opts.Manifest
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := e.Validate(m); err != nil {
		return nil, err
	}
	if e.Name != opts.Name || !identifier.MatchString(opts.Name) || nc == nil || signer == nil {
		return nil, errors.New("unexpected config secret name or missing connection/signer")
	}
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
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
	r := Request{Domain: Domain, RequestID: uuid.NewString(), Envelope: e, Recipient: identity.Recipient().String(), Reply: inbox, IssuedAt: now.Unix(), ExpiresAt: now.Add(55 * time.Second).Unix()}
	raw, err := r.Raw()
	if err != nil {
		return nil, err
	}
	r.Signature, err = signer.Sign(raw)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	digest := r.Digest()
	nodeIndex := map[string]int{}
	for i, n := range m.Nodes {
		nodeIndex[n.ID] = i
		if err = nc.Publish(Subject(n.ID), body); err != nil {
			return nil, err
		}
	}
	if err = nc.FlushWithContext(ctx); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var parts []*share.PubShare
	defer func() {
		for _, p := range parts {
			p.V.Null()
		}
	}()
	for len(parts) < m.Threshold {
		msg, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("config decrypt received %d/%d valid responses: %w", len(parts), m.Threshold, err)
		}
		if len(msg.Data) > maxMessage {
			continue
		}
		var res Response
		if json.Unmarshal(msg.Data, &res) != nil {
			continue
		}
		idx, ok := nodeIndex[res.NodeID]
		if !ok || seen[res.NodeID] || res.Domain != Domain || res.Digest != digest || !ed25519.Verify(ed25519.PublicKey(m.Nodes[idx].IdentityKey), res.Raw(), res.Signature) {
			continue
		}
		seen[res.NodeID] = true
		if res.Error == "" {
			raw, err := unseal(identity, res.Ciphertext)
			if err == nil {
				var p Partial
				err = json.Unmarshal(raw, &p)
				clear(raw)
				if err == nil && p.Index == uint32(idx) {
					part, err := verifyPartial(m, e, p, digest+"/"+res.NodeID)
					if err == nil {
						parts = append(parts, part)
					}
				}
			}
		}
		if len(parts)+len(m.Nodes)-len(seen) < m.Threshold {
			return nil, errors.New("insufficient nodes authorized or able to decrypt config")
		}
	}
	return combine(m, e, parts)
}
