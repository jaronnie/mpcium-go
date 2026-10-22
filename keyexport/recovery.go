package keyexport

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// recoveryShares reconstructs the same Shamir polynomial used by the nodes,
// without importing node-side TSS computation or its dependency replacements.
type recoveryShare struct {
	Threshold int
	ID, Share *big.Int
}
type recoveryShares []*recoveryShare

func (shares recoveryShares) ReConstruct(curve elliptic.Curve) (*big.Int, error) {
	if len(shares) == 0 || len(shares) < shares[0].Threshold+1 {
		return nil, errors.New("insufficient shares")
	}
	n := curve.Params().N
	secret := new(big.Int)
	for i, s := range shares {
		weight := big.NewInt(1)
		for j, t := range shares {
			if i == j {
				continue
			}
			denominator := new(big.Int).Sub(t.ID, s.ID)
			denominator.Mod(denominator, n)
			inverse := new(big.Int).ModInverse(denominator, n)
			if inverse == nil {
				secret.SetInt64(0)
				return nil, errors.New("duplicate share coordinates")
			}
			weight.Mul(weight, t.ID).Mul(weight, inverse).Mod(weight, n)
		}
		weight.Mul(weight, s.Share)
		secret.Add(secret, weight).Mod(secret, n)
		weight.SetInt64(0)
	}
	return secret, nil
}
