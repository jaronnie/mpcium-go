package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/jaronnie/mpcium-go/types"
)

// CredentialsVersion is the only supported project credentials format.
const CredentialsVersion = 4

// CredentialsBundle contains the project identity and trusted node public keys.
// Connection settings are provided separately to Connect.
type CredentialsBundle struct {
	AccessToken        string                       `json:"access_token,omitempty"`
	Version            int                          `json:"version"`
	ProjectID          string                       `json:"project_id"`
	NodePublicKeys     map[string]ed25519.PublicKey `json:"node_public_keys"`
	InitiatorAlgorithm types.EventInitiatorKeyType  `json:"initiator_algorithm"`
	InitiatorKey       []byte                       `json:"initiator_key"`
}

type Credentials struct {
	AccessToken    string
	ProjectID      string
	NodePublicKeys map[string]ed25519.PublicKey
	Initiator      Signer
}

// UnlockCredentials loads a single age-encrypted bundle without plaintext files.
// Password may come from a terminal, environment or application configuration.
func UnlockCredentials(path, password string) (*Credentials, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > 128*1024 {
		return nil, errors.New("credentials file too large")
	}
	return UnlockCredentialsBytes(raw, password)
}
func UnlockCredentialsBytes(encrypted []byte, password string) (*Credentials, error) {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, fmt.Errorf("unlock credentials: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > 64*1024 {
		return nil, errors.New("credentials bundle too large")
	}
	var b CredentialsBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	defer clear(b.InitiatorKey)
	return credentialsFromBundle(b)
}
func credentialsFromBundle(b CredentialsBundle) (*Credentials, error) {
	if b.Version != CredentialsVersion {
		return nil, errors.New("only V4 project credentials are supported; export a new bundle from the console")
	}
	if b.ProjectID == "" {
		return nil, errors.New("project ID is required")
	}
	if err := validateSDKNodes(b.NodePublicKeys); err != nil {
		return nil, err
	}
	signer, err := newMemorySigner(b.InitiatorAlgorithm, b.InitiatorKey)
	if err != nil {
		return nil, err
	}
	return &Credentials{AccessToken: b.AccessToken, ProjectID: b.ProjectID, NodePublicKeys: cloneSDKNodes(b.NodePublicKeys), Initiator: signer}, nil
}

// EncryptCredentialsBytes returns only age ciphertext; it never creates a file.
func EncryptCredentialsBytes(password string, b CredentialsBundle) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty credentials password")
	}
	checked, err := credentialsFromBundle(b)
	if err != nil {
		return nil, err
	}
	checked.Close()
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) > 64*1024 {
		return nil, errors.New("credentials bundle too large")
	}
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(raw); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return encrypted.Bytes(), nil
}

// EncryptCredentials writes a new 0600 file and refuses overwrites.
func EncryptCredentials(path, password string, bundle CredentialsBundle) error {
	encrypted, err := EncryptCredentialsBytes(password, bundle)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(encrypted); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func newMemorySigner(algorithm types.EventInitiatorKeyType, raw []byte) (*LocalSigner, error) {
	s := &LocalSigner{keyType: algorithm}
	var err error
	switch algorithm {
	case types.EventInitiatorKeyTypeEd25519:
		err = s.loadEd25519Key(raw)
	case types.EventInitiatorKeyTypeP256:
		err = s.loadP256Key(raw)
	default:
		err = errors.New("unsupported initiator algorithm")
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Close performs best-effort cleanup. Go does not guarantee erasure of all copies.
func (c *Credentials) Close() {
	if s, ok := c.Initiator.(*LocalSigner); ok {
		clear(s.ed25519Key)
		s.ed25519Key = nil
		if s.p256Key != nil {
			s.p256Key.D.SetInt64(0)
			s.p256Key = nil
		}
	}
	c.NodePublicKeys = nil
	c.AccessToken = ""
	c.Initiator = nil
}
