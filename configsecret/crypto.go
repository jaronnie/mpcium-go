// Package configsecret implements independent threshold-DH envelope encryption
// for application configuration. It never reads or exports wallet keys.
package configsecret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/proof"
	"go.dedis.ch/kyber/v4/share"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

const Domain = "mpcium/config-secret/v1"
const MaxPlaintext = 16 * 1024

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var projectIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func suite() *edwards25519.SuiteEd25519 { return edwards25519.NewBlakeSHA256Ed25519() }

// Manifest is public, but must be pinned in trusted client and node config.
// Node order defines Shamir indices (zero based in Kyber).
type Manifest struct {
	Domain      string   `json:"domain"`
	ProjectID   string   `json:"project_id"`
	KeyID       string   `json:"key_id"`
	Version     int      `json:"version"`
	Threshold   int      `json:"threshold"`
	Nodes       []Node   `json:"nodes"`
	Commitments [][]byte `json:"commitments"`
}
type Node struct {
	ID          string `json:"id"`
	IdentityKey []byte `json:"identity_key"`
}

func (m Manifest) Validate() error {
	if m.Domain != Domain || !projectIdentifier.MatchString(m.ProjectID) || !identifier.MatchString(m.KeyID) || m.Version < 1 || m.Threshold < 2 || m.Threshold > len(m.Nodes) || len(m.Nodes) > 32 || len(m.Commitments) != m.Threshold {
		return errors.New("invalid config key manifest")
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, n := range m.Nodes {
		if !identifier.MatchString(n.ID) || len(n.IdentityKey) != ed25519.PublicKeySize || ids[n.ID] || keys[string(n.IdentityKey)] {
			return errors.New("invalid or duplicate config key node")
		}
		ids[n.ID], keys[string(n.IdentityKey)] = true, true
	}
	for _, c := range m.Commitments {
		if _, err := parsePoint(c); err != nil {
			return err
		}
	}
	pub, err := m.polynomial()
	if err != nil {
		return err
	}
	for i := range m.Nodes {
		b, _ := pub.Eval(uint32(i)).V.MarshalBinary()
		if _, err := parsePoint(b); err != nil {
			return errors.New("invalid public share")
		}
	}
	return nil
}
func (m Manifest) Fingerprint() string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (m Manifest) polynomial() (*share.PubPoly, error) {
	s := suite()
	points := make([]kyber.Point, len(m.Commitments))
	for i, b := range m.Commitments {
		p, err := parsePoint(b)
		if err != nil {
			return nil, err
		}
		points[i] = p
	}
	return share.NewPubPoly(s, nil, points), nil
}

// Reject noncanonical encodings, identity, and all non-prime-order components.
func parsePoint(b []byte) (kyber.Point, error) {
	s := suite()
	p := s.Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	canonical, err := p.MarshalBinary()
	if err != nil || !bytes.Equal(b, canonical) || p.Equal(s.Point().Null()) {
		return nil, errors.New("invalid config point")
	}
	eight := s.Scalar().SetInt64(8)
	q := s.Point().Mul(eight, p)
	q.Mul(s.Scalar().Inv(eight), q)
	if !q.Equal(p) {
		return nil, errors.New("point outside prime-order subgroup")
	}
	return p, nil
}

type sealedShare struct {
	ManifestHash string `json:"manifest_hash"`
	Index        uint32 `json:"index"`
	Scalar       []byte `json:"scalar"`
}

// Generate uses a trusted offline dealer. It does NOT perform distributed DKG.
// Only individually age-encrypted shares and a public manifest leave this call.
func Generate(project, keyID string, version, threshold int, nodes []Node) (Manifest, map[string][]byte, error) {
	m := Manifest{Domain: Domain, ProjectID: project, KeyID: keyID, Version: version, Threshold: threshold, Nodes: nodes}
	if threshold < 2 || threshold > len(nodes) || len(nodes) > 32 {
		return m, nil, errors.New("invalid threshold")
	}
	s := suite()
	poly := share.NewPriPoly(s, uint32(threshold), nil, s.RandomStream())
	defer func() {
		for _, c := range poly.Coefficients() {
			c.Zero()
		}
	}()
	_, commits := poly.Commit(nil).Info()
	for _, p := range commits {
		b, err := p.MarshalBinary()
		if err != nil {
			return m, nil, err
		}
		m.Commitments = append(m.Commitments, b)
	}
	if err := m.Validate(); err != nil {
		return m, nil, err
	}
	out := map[string][]byte{}
	for i, n := range nodes {
		sshKey, err := ssh.NewPublicKey(ed25519.PublicKey(n.IdentityKey))
		if err != nil {
			return m, nil, err
		}
		recipient, err := agessh.NewEd25519Recipient(sshKey)
		if err != nil {
			return m, nil, err
		}
		v := poly.Eval(uint32(i))
		raw, err := v.V.MarshalBinary()
		v.V.Zero()
		if err != nil {
			return m, nil, err
		}
		plain, err := json.Marshal(sealedShare{m.Fingerprint(), uint32(i), raw})
		clear(raw)
		if err != nil {
			return m, nil, err
		}
		encrypted, err := seal(recipient, plain)
		clear(plain)
		if err != nil {
			return m, nil, err
		}
		out[n.ID] = encrypted
	}
	return m, out, nil
}
func seal(recipient age.Recipient, plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(plain); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func unseal(identity age.Identity, b []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(b), identity)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64*1024 {
		clear(raw)
		return nil, errors.New("decrypted message too large")
	}
	return raw, nil
}

// Envelope authenticates project, key version, secret name and key manifest.
// Ciphertexts contain no plaintext config or long-lived decryption secret.
type Envelope struct {
	Domain       string `json:"domain"`
	ManifestHash string `json:"manifest_hash"`
	ProjectID    string `json:"project_id"`
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	Name         string `json:"name"`
	Ephemeral    []byte `json:"ephemeral"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

func (e Envelope) aad() []byte { e.Ciphertext = nil; b, _ := json.Marshal(e); return b }
func (e Envelope) Validate(m Manifest) error {
	if e.Domain != Domain || e.ManifestHash != m.Fingerprint() || e.ProjectID != m.ProjectID || e.KeyID != m.KeyID || e.Version != m.Version || !identifier.MatchString(e.Name) || len(e.Nonce) != 12 || len(e.Ciphertext) < 16 || len(e.Ciphertext) > MaxPlaintext+16 {
		return errors.New("invalid config ciphertext or key version")
	}
	_, err := parsePoint(e.Ephemeral)
	return err
}
func aead(shared kyber.Point, e Envelope) (cipher.AEAD, error) {
	raw, err := shared.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(hkdf.New(sha256.New, raw, nil, append([]byte(Domain+"/aes-key/"), e.aad()...)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt is local public-key encryption. Possession of public metadata permits
// encryption, not decryption. The trusted delivery channel controls config writes.
func Encrypt(m Manifest, name string, plaintext []byte) (Envelope, error) {
	if err := m.Validate(); err != nil {
		return Envelope{}, err
	}
	if len(plaintext) > MaxPlaintext || !identifier.MatchString(name) {
		return Envelope{}, errors.New("invalid secret name or size")
	}
	s := suite()
	r := s.Scalar().Pick(s.RandomStream())
	defer r.Zero()
	pub, err := parsePoint(m.Commitments[0])
	if err != nil {
		return Envelope{}, err
	}
	ephemeral, _ := s.Point().Mul(r, nil).MarshalBinary()
	e := Envelope{Domain: Domain, ManifestHash: m.Fingerprint(), ProjectID: m.ProjectID, KeyID: m.KeyID, Version: m.Version, Name: name, Ephemeral: ephemeral, Nonce: make([]byte, 12)}
	if _, err = rand.Read(e.Nonce); err != nil {
		return Envelope{}, err
	}
	shared := s.Point().Mul(r, pub)
	defer shared.Null()
	cipher, err := aead(shared, e)
	if err != nil {
		return Envelope{}, err
	}
	e.Ciphertext = cipher.Seal(nil, e.Nonce, plaintext, e.aad())
	return e, nil
}

type Partial struct {
	Index uint32 `json:"index"`
	Point []byte `json:"point"`
	Proof []byte `json:"proof"`
}

func predicate() proof.Predicate {
	return proof.And(proof.Rep("X", "x", "G"), proof.Rep("D", "x", "R"))
}
func partialPoints(m Manifest, index uint32, e Envelope, d kyber.Point) (map[string]kyber.Point, error) {
	if int(index) >= len(m.Nodes) {
		return nil, errors.New("invalid share index")
	}
	poly, err := m.polynomial()
	if err != nil {
		return nil, err
	}
	r, err := parsePoint(e.Ephemeral)
	if err != nil {
		return nil, err
	}
	return map[string]kyber.Point{"G": suite().Point().Base(), "X": poly.Eval(index).V, "R": r, "D": d}, nil
}
func proofDomain(binding string) string { return Domain + "/partial/" + binding }
func partialDecrypt(m Manifest, e Envelope, index uint32, scalar kyber.Scalar, binding string) (Partial, error) {
	r, err := parsePoint(e.Ephemeral)
	if err != nil {
		return Partial{}, err
	}
	d := suite().Point().Mul(scalar, r)
	defer d.Null()
	points, err := partialPoints(m, index, e, d)
	if err != nil {
		return Partial{}, err
	}
	b, err := proof.HashProve(suite(), proofDomain(binding), predicate().Prover(suite(), map[string]kyber.Scalar{"x": scalar}, points, nil))
	if err != nil {
		return Partial{}, err
	}
	raw, err := d.MarshalBinary()
	return Partial{index, raw, b}, err
}
func verifyPartial(m Manifest, e Envelope, p Partial, binding string) (*share.PubShare, error) {
	if len(p.Proof) > 4096 {
		return nil, errors.New("oversized partial proof")
	}
	d, err := parsePoint(p.Point)
	if err != nil {
		return nil, err
	}
	points, err := partialPoints(m, p.Index, e, d)
	if err != nil {
		return nil, err
	}
	if err = proof.HashVerify(suite(), proofDomain(binding), predicate().Verifier(suite(), points), p.Proof); err != nil {
		return nil, fmt.Errorf("invalid decryption proof: %w", err)
	}
	return &share.PubShare{I: p.Index, V: d}, nil
}
func combine(m Manifest, e Envelope, parts []*share.PubShare) ([]byte, error) {
	if len(parts) < m.Threshold {
		return nil, errors.New("insufficient config decryption shares")
	}
	shared, err := share.RecoverCommit(suite(), parts, uint32(m.Threshold), uint32(len(m.Nodes)))
	if err != nil {
		return nil, err
	}
	defer shared.Null()
	cipher, err := aead(shared, e)
	if err != nil {
		return nil, err
	}
	return cipher.Open(nil, e.Nonce, e.Ciphertext, e.aad())
}
