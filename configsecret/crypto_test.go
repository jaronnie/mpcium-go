package configsecret

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"filippo.io/age/agessh"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
)

func fixture(t *testing.T) (Manifest, []kyber.Scalar) {
	t.Helper()
	nodes := []Node{}
	keys := []ed25519.PrivateKey{}
	for _, id := range []string{"node0", "node1", "node2"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		nodes = append(nodes, Node{id, pub})
		keys = append(keys, key)
	}
	m, encrypted, err := Generate("rebate", "database", 1, 2, nodes)
	require.NoError(t, err)
	var shares []kyber.Scalar
	for i, n := range nodes {
		id, err := agessh.NewEd25519Identity(keys[i])
		require.NoError(t, err)
		raw, err := unseal(id, encrypted[n.ID])
		require.NoError(t, err)
		var sh sealedShare
		require.NoError(t, json.Unmarshal(raw, &sh))
		clear(raw)
		s := suite().Scalar()
		require.NoError(t, s.UnmarshalBinary(sh.Scalar))
		clear(sh.Scalar)
		shares = append(shares, s)
		wrong, _ := agessh.NewEd25519Identity(keys[(i+1)%3])
		_, err = unseal(wrong, encrypted[n.ID])
		require.Error(t, err)
	}
	t.Cleanup(func() {
		for _, s := range shares {
			s.Zero()
		}
	})
	return m, shares
}
func TestThresholdEnvelopeAllPairs(t *testing.T) {
	m, shares := fixture(t)
	plain := []byte("postgres://user:independent-password@db/service")
	e, err := Encrypt(m, "database-url", plain)
	require.NoError(t, err)
	require.NoError(t, e.Validate(m))
	e2, err := Encrypt(m, "database-url", plain)
	require.NoError(t, err)
	require.NotEqual(t, e, e2)
	for _, pair := range [][]int{{0, 1}, {0, 2}, {1, 2}} {
		var parts []*share.PubShare
		for _, i := range pair {
			p, err := partialDecrypt(m, e, uint32(i), shares[i], "request/node")
			require.NoError(t, err)
			part, err := verifyPartial(m, e, p, "request/node")
			require.NoError(t, err)
			parts = append(parts, part)
		}
		_, err = combine(m, e, parts[:1])
		require.Error(t, err)
		got, err := combine(m, e, parts)
		require.NoError(t, err)
		require.Equal(t, plain, got)
		clear(got)
	}
}
func TestTamperingAndProofBinding(t *testing.T) {
	m, shares := fixture(t)
	e, err := Encrypt(m, "password", []byte("secret"))
	require.NoError(t, err)
	p, err := partialDecrypt(m, e, 0, shares[0], "request-a/node0")
	require.NoError(t, err)
	_, err = verifyPartial(m, e, p, "request-b/node0")
	require.Error(t, err)
	wrongShare, err := partialDecrypt(m, e, 0, shares[1], "request-a/node0")
	require.NoError(t, err)
	_, err = verifyPartial(m, e, wrongShare, "request-a/node0")
	require.Error(t, err)
	forged := p
	forged.Point, _ = suite().Point().Base().MarshalBinary()
	_, err = verifyPartial(m, e, forged, "request-a/node0")
	require.Error(t, err)
	forged = p
	forged.Proof = make([]byte, len(p.Proof))
	_, err = verifyPartial(m, e, forged, "request-a/node0")
	require.Error(t, err)
	forged = p
	forged.Index = 1
	_, err = verifyPartial(m, e, forged, "request-a/node0")
	require.Error(t, err)
	e2, err := Encrypt(m, "password", []byte("other"))
	require.NoError(t, err)
	_, err = verifyPartial(m, e2, p, "request-a/node0")
	require.Error(t, err)
	var parts []*share.PubShare
	for i := 0; i < 2; i++ {
		p, err := partialDecrypt(m, e, uint32(i), shares[i], "req")
		require.NoError(t, err)
		part, err := verifyPartial(m, e, p, "req")
		require.NoError(t, err)
		parts = append(parts, part)
	}
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Ciphertext = append([]byte(nil), e.Ciphertext...); e.Ciphertext[0] ^= 1 },
		func(e *Envelope) { e.Name = "different" }, func(e *Envelope) { e.Version++ }, func(e *Envelope) { e.ProjectID = "collection" }, func(e *Envelope) { e.KeyID = "other" },
	} {
		tampered := e
		mutate(&tampered)
		_, err = combine(m, tampered, parts)
		require.Error(t, err)
	}
	wrong := m
	wrong.Version++
	require.Error(t, e.Validate(wrong))
}
func TestRejectNonPrimeOrderPointsAndBadManifest(t *testing.T) {
	s := suite()
	identity, _ := s.Point().Null().MarshalBinary()
	_, err := parsePoint(identity)
	require.Error(t, err)
	torsion := s.Point()
	require.NoError(t, torsion.UnmarshalBinary(make([]byte, 32)))
	for _, p := range []kyber.Point{torsion, s.Point().Add(s.Point().Base(), torsion)} {
		raw, _ := p.MarshalBinary()
		_, err := parsePoint(raw)
		require.Error(t, err)
	}
	m, _ := fixture(t)
	bad := m
	bad.Nodes = append([]Node(nil), m.Nodes...)
	bad.Nodes[1] = bad.Nodes[0]
	require.Error(t, bad.Validate())
	bad = m
	bad.Threshold = 1
	require.Error(t, bad.Validate())
	bad = m
	bad.Commitments = append([][]byte(nil), m.Commitments...)
	bad.Commitments[0] = identity
	require.Error(t, bad.Validate())
	_, err = Encrypt(m, "invalid.name", []byte("x"))
	require.Error(t, err)
	_, err = Encrypt(m, "password", make([]byte, MaxPlaintext+1))
	require.Error(t, err)
}
