package keyexport

import (
	"bytes"
	"errors"
	"math/big"
	"strconv"
)

// RecoverBusiness combines authenticated node recovery material. The policy must
// be agreed by at least its threshold of distinct pinned nodes before this call.
func RecoverBusiness(p Policy, parts map[string]Share, digest string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	curve := Curve(p.KeyType)
	shares := recoveryShares{}
	seen := map[string]bool{}
	defer func() {
		for _, s := range shares {
			s.Share.SetInt64(0)
		}
	}()
	for _, node := range p.Participants {
		part, ok := parts[node]
		if !ok || part.NodeID != node || part.RequestDigest != digest || !bytes.Equal(part.PublicKey, p.PublicKey) || len(part.ID) > 256 || len(part.Value) > 32 {
			continue
		}
		id := new(big.Int).SetBytes(part.ID)
		id.Mod(id, curve.Params().N)
		expected := new(big.Int).SetBytes([]byte(node + ":" + strconv.Itoa(p.KeyVersion)))
		expected.Mod(expected, curve.Params().N)
		value := new(big.Int).SetBytes(part.Value)
		if id.Sign() == 0 || id.Cmp(expected) != 0 || seen[id.String()] || value.Sign() <= 0 || value.Cmp(curve.Params().N) >= 0 {
			value.SetInt64(0)
			continue
		}
		seen[id.String()] = true
		shares = append(shares, &recoveryShare{Threshold: p.Threshold - 1, ID: id, Share: value})
	}
	if len(shares) < p.Threshold {
		return nil, errors.New("insufficient valid wallet shares")
	}
	// A faulty share must not suppress a valid quorum. Try threshold-sized subsets
	// with a small cluster bound (the SDK credentials support at most 8 nodes).
	var secret []byte
	var visit func(int, recoveryShares) bool
	visit = func(start int, selected recoveryShares) bool {
		if len(selected) == p.Threshold {
			scalar, err := selected.ReConstruct(curve)
			if err != nil {
				return false
			}
			defer scalar.SetInt64(0)
			if scalar.Sign() > 0 && bytes.Equal(PublicKey(p.KeyType, scalar), p.PublicKey) {
				secret = scalar.FillBytes(make([]byte, 32))
				return true
			}
			return false
		}
		for i := start; i < len(shares); i++ {
			if visit(i+1, append(selected, shares[i])) {
				return true
			}
		}
		return false
	}
	if !visit(0, nil) {
		return nil, errors.New("wallet recovery does not match public key")
	}
	return secret, nil
}
