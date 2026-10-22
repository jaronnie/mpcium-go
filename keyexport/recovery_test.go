package keyexport

import (
	"bytes"
	"math/big"
	"strconv"
	"testing"

	"github.com/jaronnie/mpcium-go/types"
)

func TestRecoverBusinessBothCurves(t *testing.T) {
	for _, kind := range []types.KeyType{types.KeyTypeSecp256k1, types.KeyTypeEd25519} {
		t.Run(string(kind), func(t *testing.T) {
			secret := big.NewInt(12345)
			p := Policy{WalletID: "wallet", KeyType: kind, KeyVersion: 1, Threshold: 2, Participants: []string{"node0", "node1", "node2"}, InitiatorFingerprint: Fingerprint([]byte("initiator")), PublicKey: PublicKey(kind, secret)}
			parts := map[string]Share{}
			n := Curve(kind).Params().N
			for _, node := range p.Participants {
				x := new(big.Int).SetBytes([]byte(node + ":" + strconv.Itoa(p.KeyVersion)))
				x.Mod(x, n)
				y := new(big.Int).Mul(x, big.NewInt(42))
				y.Add(y, secret).Mod(y, n)
				parts[node] = Share{RequestDigest: "request", NodeID: node, ID: x.Bytes(), Value: y.Bytes(), PublicKey: p.PublicKey}
			}
			for _, missing := range p.Participants {
				quorum := map[string]Share{}
				for node, s := range parts {
					if node != missing {
						quorum[node] = s
					}
				}
				got, err := RecoverBusiness(p, quorum, "request")
				if err != nil || !bytes.Equal(got, secret.FillBytes(make([]byte, 32))) {
					t.Fatalf("missing %s: %x %v", missing, got, err)
				}
				clear(got)
			}
			// One corrupt node must not suppress a healthy two-node quorum.
			corrupt := parts["node0"]
			corrupt.Value = []byte{1}
			parts["node0"] = corrupt
			got, err := RecoverBusiness(p, parts, "request")
			if err != nil || new(big.Int).SetBytes(got).Cmp(secret) != 0 {
				t.Fatalf("faulty share: %v", err)
			}
			clear(got)
			if _, err = RecoverBusiness(p, parts, "other-request"); err == nil {
				t.Fatal("accepted wrong request")
			}
			delete(parts, "node1")
			if _, err = RecoverBusiness(p, parts, "request"); err == nil {
				t.Fatal("accepted corrupt quorum")
			}
		})
	}
}

func TestReconstructRejectsInvalidQuorum(t *testing.T) {
	curve := Curve(types.KeyTypeSecp256k1)
	for _, shares := range []recoveryShares{nil, {{Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(2)}}, {{Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(2)}, {Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(3)}}} {
		if _, err := shares.ReConstruct(curve); err == nil {
			t.Fatal("accepted invalid shares")
		}
	}
}
