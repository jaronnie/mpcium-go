package mpcium

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jaronnie/mpcium-go/types"
	"github.com/stretchr/testify/require"
)

func TestCreateAndExportValidatesBeforeCreatingWallet(t *testing.T) {
	pinned := map[string]ed25519.PublicKey{"n0": make([]byte, 32), "n1": make([]byte, 32), "n2": make([]byte, 32)}
	valid := WalletExportOptions{KeyType: types.KeyTypeSecp256k1, Threshold: 2, Participants: []string{"n0", "n1", "n2"}, NodePublicKeys: pinned}
	signer := &MockSigner{}
	signer.On("PublicKey").Return(hex.EncodeToString(make([]byte, 32)), nil)
	// No connection or broker: preflight must fail without network side effects.
	c := &mpcClient{projectID: "rebate", signer: signer}
	for _, mutate := range []func(*WalletExportOptions){
		func(o *WalletExportOptions) { o.Threshold = 1 }, func(o *WalletExportOptions) { o.Threshold = 4 }, func(o *WalletExportOptions) { o.KeyType = "unsupported" }, func(o *WalletExportOptions) { o.Participants = []string{"n0", "n0"} }, func(o *WalletExportOptions) { o.NodePublicKeys = nil },
	} {
		opts := valid
		mutate(&opts)
		_, err := c.CreateWalletAndExport(context.Background(), "rebate-wallet", opts)
		require.Error(t, err)
	}
	_, err := c.CreateWalletAndExport(context.Background(), "wallet.*", valid)
	require.Error(t, err)
	c.projectID = ""
	_, err = c.CreateWalletAndExport(context.Background(), "rebate-wallet", valid)
	require.Error(t, err)
	c.projectID = "rebate"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.CreateWalletAndExport(ctx, "rebate-wallet", valid)
	require.True(t, errors.Is(err, context.Canceled))
}
