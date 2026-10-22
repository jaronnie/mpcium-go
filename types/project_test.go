package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProjectRawBindsIdentityAndOperation(t *testing.T) {
	k := &GenerateKeyMessage{ProjectID: "a", WalletID: "a-wallet"}
	a, e := k.Raw()
	require.NoError(t, e)
	k.ProjectID = "b"
	b, e := k.Raw()
	require.NoError(t, e)
	require.NotEqual(t, a, b)
	s := &SignTxMessage{ProjectID: "a", WalletID: "a-wallet"}
	b, e = s.Raw()
	require.NoError(t, e)
	require.NotEqual(t, a, b)
	r := &ResharingMessage{ProjectID: "a", WalletID: "a-wallet"}
	a, e = r.Raw()
	require.NoError(t, e)
	r.ProjectID = "b"
	b, e = r.Raw()
	require.NoError(t, e)
	require.NotEqual(t, a, b)
	legacy := &GenerateKeyMessage{WalletID: "wallet"}
	a, e = legacy.Raw()
	require.NoError(t, e)
	require.Equal(t, []byte("wallet"), a)
}
