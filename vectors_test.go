package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVectors(t *testing.T) {

	// Alice
	alicePrivateKeyHex := "0500ff0500fbfc04020a04010001050701ff01fcfc00fbff00fd010601fc00fffefd01f901f700fe000401ff0306fdff000102ff000204fdfd02ff01fc0000010401fd0000fffeff0500"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	err = alicePrivateKey.Unmarshal(alicePrivateKeyBytes)
	require.NoError(t, err)

	alicePublicKey, err := DerivePublicKey(alicePrivateKey)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "06fc0009fc01ff0201060304fcf501010004020104fd02fff8fefffc0103030100ffff040304ff0102fa0002ff000101fafdfe03ff0400fe01fa00fd0101ff03fe020101030200ff0001"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	err = bobPrivateKey.Unmarshal(bobPrivateKeyBytes)
	require.NoError(t, err)

	bobPublicKey, err := DerivePublicKey(bobPrivateKey)
	require.NoError(t, err)

	// NIKE
	bobShared, err := GroupAction(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)

	aliceShared, err := GroupAction(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)

	bobSharedBytes, err := bobShared.Marshal()
	require.NoError(t, err)

	aliceSharedBytes, err := aliceShared.Marshal()
	require.NoError(t, err)

	require.Equal(t, bobSharedBytes, aliceSharedBytes)

}
