package mpcium

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/jaronnie/mpcium-go/configsecret"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/sdkapi"
	"github.com/nats-io/nats.go"
)

type businessGroup struct {
	result sdkapi.Result
	nodes  map[string]bool
	parts  map[string]configsecret.Partial
	shares map[string]keyexport.Share
}

func (c *mpcClient) business(ctx context.Context, operation, id string, data []byte) ([]byte, error) {
	if c.natsConn == nil || c.signer == nil {
		return nil, errors.New("SDK connection and identity required")
	}
	if err := validateSDKNodes(c.nodePublicKeys); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	recipient, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	inbox := nats.NewInbox()
	sub, err := c.natsConn.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err = sub.SetPendingLimits(128, 128*sdkapi.MaxMessage); err != nil {
		return nil, err
	}
	if err = c.natsConn.FlushWithContext(ctx); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	request := sdkapi.Request{Domain: sdkapi.Domain, ProjectID: c.projectID, RequestID: uuid.NewString(), Operation: operation, ResourceID: id, Data: data, Recipient: recipient.Recipient().String(), Reply: inbox, ExpiresAt: deadline.Unix()}
	if err = request.Validate(time.Now()); err != nil {
		return nil, err
	}
	raw, err := request.Raw()
	if err != nil {
		return nil, err
	}
	request.Signature, err = c.signer.Sign(raw)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	for node := range c.nodePublicKeys {
		if err = c.natsConn.PublishRequest(sdkapi.Subject(node), inbox, encoded); err != nil {
			return nil, err
		}
	}
	digest := request.Digest()
	seen := map[string]bool{}
	groups := map[string]*businessGroup{}
	sensitive := [][]byte{}
	defer func() {
		for _, b := range sensitive {
			clear(b)
		}
	}()
	for len(seen) < len(c.nodePublicKeys) {
		msg, err := sub.NextMsgWithContext(ctx)
		// Each node has its own subject. An offline node must not abort a valid
		// threshold operation while the other nodes are still replying.
		if errors.Is(err, nats.ErrNoResponders) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("SDK node operation (check updated node services): %w", err)
		}
		if len(msg.Data) > sdkapi.MaxMessage {
			continue
		}
		var response sdkapi.Response
		if json.Unmarshal(msg.Data, &response) != nil || seen[response.NodeID] || !response.Verify(response.NodeID, c.nodePublicKeys[response.NodeID], digest) {
			continue
		}
		result, err := sdkapi.Decrypt(recipient, response.Ciphertext)
		if err != nil {
			continue
		}
		seen[response.NodeID] = true
		if result.Share != nil {
			sensitive = append(sensitive, result.Share.Value)
		}
		if result.Error != "" {
			continue
		}
		groupID, threshold, err := c.validateBusinessResult(&request, response.NodeID, result)
		if err != nil {
			continue
		}
		group := groups[groupID]
		if group == nil {
			group = &businessGroup{result: result, nodes: map[string]bool{}, parts: map[string]configsecret.Partial{}, shares: map[string]keyexport.Share{}}
			groups[groupID] = group
		}
		group.nodes[response.NodeID] = true
		if result.Partial != nil {
			group.parts[response.NodeID] = *result.Partial
		}
		if result.Share != nil {
			group.shares[response.NodeID] = *result.Share
		}
		if len(group.nodes) < threshold {
			continue
		}
		switch operation {
		case "encryption-key":
			return json.Marshal(group.result.Manifest)
		case "decrypt", "decrypt-stored":
			plain, err := configsecret.RecoverBusiness(*group.result.Manifest, *group.result.Envelope, group.parts, digest)
			if err == nil {
				return plain, nil
			}
		case "export-wallet":
			secret, err := keyexport.RecoverBusiness(*group.result.Policy, group.shares, digest)
			if err == nil {
				return secret, nil
			}
		}
	}
	return nil, errors.New("insufficient matching, authorized MPC node results")
}
func (c *mpcClient) validateBusinessResult(r *sdkapi.Request, node string, result sdkapi.Result) (string, int, error) {
	if r.Operation == "export-wallet" {
		p := result.Policy
		if p == nil || result.Share == nil || p.Validate() != nil || p.ProjectID != c.projectID || p.WalletID != r.ResourceID {
			return "", 0, errors.New("invalid wallet result")
		}
		public, err := c.signer.PublicKey()
		if err != nil {
			return "", 0, err
		}
		pub, err := hex.DecodeString(public)
		if err != nil || p.InitiatorFingerprint != keyexport.Fingerprint(pub) {
			return "", 0, errors.New("wrong initiator")
		}
		member := false
		for _, id := range p.Participants {
			if len(c.nodePublicKeys[id]) == 0 {
				return "", 0, errors.New("untrusted participant")
			}
			member = member || id == node
		}
		if !member {
			return "", 0, errors.New("nonmember wallet response")
		}
		b, _ := json.Marshal(p)
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:]), p.Threshold, nil
	}
	m := result.Manifest
	if m == nil || m.Validate() != nil || m.ProjectID != c.projectID || m.KeyID != r.ResourceID {
		return "", 0, errors.New("invalid data result")
	}
	member := false
	for _, n := range m.Nodes {
		if !bytes.Equal(c.nodePublicKeys[n.ID], n.IdentityKey) {
			return "", 0, errors.New("untrusted data node")
		}
		member = member || n.ID == node
	}
	if !member {
		return "", 0, errors.New("nonmember data response")
	}
	key := m.Fingerprint()
	if r.Operation != "encryption-key" {
		e := result.Envelope
		if e == nil || result.Partial == nil || e.Validate(*m) != nil || e.Name != "data" {
			return "", 0, errors.New("invalid decrypt result")
		}
		if r.Operation == "decrypt" {
			var requested configsecret.Envelope
			if json.Unmarshal(r.Data, &requested) != nil {
				return "", 0, errors.New("invalid requested ciphertext")
			}
			a, _ := json.Marshal(requested)
			b, _ := json.Marshal(e)
			if !bytes.Equal(a, b) {
				return "", 0, errors.New("ciphertext differs")
			}
		}
		b, _ := json.Marshal(e)
		h := sha256.Sum256(b)
		key += "/" + hex.EncodeToString(h[:])
	}
	return key, m.Threshold, nil
}

// EncryptData uses the public key agreed by the MPC nodes. Plaintext stays on
// the caller's machine; only the returned ciphertext needs business storage.
func (c *mpcClient) EncryptData(ctx context.Context, dataID string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > sdkapi.DataLimit {
		return nil, errors.New("plaintext must contain 1–16384 bytes")
	}
	raw, err := c.business(ctx, "encryption-key", dataID, nil)
	if err != nil {
		return nil, err
	}
	var manifest configsecret.Manifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	envelope, err := configsecret.Encrypt(manifest, "data", plaintext)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}
func (c *mpcClient) DecryptData(ctx context.Context, dataID string, ciphertext []byte) ([]byte, error) {
	return c.business(ctx, "decrypt", dataID, ciphertext)
}
func (c *mpcClient) DecryptStoredData(ctx context.Context, dataID string) ([]byte, error) {
	return c.business(ctx, "decrypt-stored", dataID, nil)
}

// ExportWallet reconstructs the private scalar only on the caller's machine.
// Ed25519 returns an MPC scalar, not a seed. The caller must clear the result.
func (c *mpcClient) ExportWallet(ctx context.Context, walletID string) ([]byte, error) {
	return c.business(ctx, "export-wallet", walletID, nil)
}
