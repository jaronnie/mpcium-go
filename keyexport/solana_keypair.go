package keyexport

import (
	"bytes"
	"errors"
	"github.com/jaronnie/mpcium-go/solanaseed"
	"github.com/jaronnie/mpcium-go/types"
	"math/big"
	"strconv"
)

// RecoverSolanaKeypair recovers a seed only after two independently authenticated
// signing shares AND recovery shares agree with the wallet's pinned public key.
func RecoverSolanaKeypair(p Policy, parts map[string]Share, digest string) ([]byte, error) {
	if p.KeyType != types.KeyTypeEd25519 || len(p.Participants) > 8 {
		return nil, errors.New("standard Solana wallet required")
	}
	scalar, err := RecoverBusiness(p, parts, digest)
	if err != nil {
		return nil, err
	}
	defer clear(scalar)
	groups := map[string]recoveryShares{}
	defer func() {
		for _, group := range groups {
			for _, s := range group {
				s.Share.SetInt64(0)
			}
		}
	}()
	for _, node := range p.Participants {
		part, ok := parts[node]
		if !ok || part.NodeID != node || part.RequestDigest != digest || !bytes.Equal(part.PublicKey, p.PublicKey) || len(part.SeedShare) == 0 || len(part.SeedShare) > 32 || len(part.ID) > 256 || solanaseed.Validate(part.SeedEnvelope, p.WalletID, p.PublicKey) != nil {
			continue
		}
		id := new(big.Int).SetBytes(part.ID)
		id.Mod(id, Curve(p.KeyType).Params().N)
		expected := new(big.Int).SetBytes([]byte(node + ":" + strconv.Itoa(p.KeyVersion)))
		expected.Mod(expected, Curve(p.KeyType).Params().N)
		v := new(big.Int).SetBytes(part.SeedShare)
		if id.Sign() == 0 || id.Cmp(expected) != 0 || v.Sign() <= 0 || v.Cmp(Curve(p.KeyType).Params().N) >= 0 {
			v.SetInt64(0)
			continue
		}
		groups[string(part.SeedEnvelope)] = append(groups[string(part.SeedEnvelope)], &recoveryShare{Threshold: p.Threshold - 1, ID: id, Share: v})
	}
	for envelope, group := range groups {
		var visit func(int, recoveryShares) ([]byte, error)
		visit = func(start int, selected recoveryShares) ([]byte, error) {
			if len(selected) == p.Threshold {
				key, err := selected.ReConstruct(Curve(p.KeyType))
				if err != nil {
					return nil, err
				}
				defer key.SetInt64(0)
				raw := key.FillBytes(make([]byte, 32))
				defer clear(raw)
				private, err := solanaseed.Open([]byte(envelope), raw, p.WalletID, p.PublicKey)
				if err != nil {
					return nil, err
				}
				a, err := solanaseed.Scalar(private[:32])
				defer clear(a)
				if err != nil || !bytes.Equal(a, scalar) {
					clear(private)
					return nil, errors.New("seed and signing shares differ")
				}
				return private, nil
			}
			for i := start; i < len(group); i++ {
				if private, err := visit(i+1, append(selected, group[i])); err == nil {
					return private, nil
				}
			}
			return nil, errors.New("insufficient valid seed recovery shares")
		}
		if private, err := visit(0, nil); err == nil {
			return private, nil
		}
	}
	return nil, errors.New("wallet has no valid standard seed recovery quorum")
}
