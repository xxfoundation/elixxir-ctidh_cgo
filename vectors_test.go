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

	alicePublicKeyHex := "a9f14cf61e8c8b9bf701c704ed66324ec3813eb7869106d636e4f72b09ac07e44979d45634f616ae12d876aec0de546f21cd9219d47e07da0929ec456d939338"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.Unmarshal(alicePublicKeyBytes)
	require.NoError(t, err)

	/*
		alicePublicKey, err := DerivePublicKey(alicePrivateKey)
		require.NoError(t, err)

		alicePublicKeyBytes, err := alicePublicKey.Marshal()
		require.NoError(t, err)
		t.Logf("alicePublicKeyBytes %x", alicePublicKeyBytes)
	*/
	// Bob
	bobPrivateKeyHex := "06fc0009fc01ff0201060304fcf501010004020104fd02fff8fefffc0103030100ffff040304ff0102fa0002ff000101fafdfe03ff0400fe01fa00fd0101ff03fe020101030200ff0001"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	err = bobPrivateKey.Unmarshal(bobPrivateKeyBytes)
	require.NoError(t, err)

	/*
		bobPublicKey, err := DerivePublicKey(bobPrivateKey)
		require.NoError(t, err)

		bobPublicKeyBytes, err := bobPublicKey.Marshal()
		require.NoError(t, err)
		t.Logf("bobPublicKeyBytes %x", bobPublicKeyBytes)
	*/

	bobPublicKeyHex := "1e4a6a12ae0218f3eda0213d28e640bf4e39a56847b0374576cb02a18219d7c64ea7e87414ce20eb45566f6cf6243e8fb6f4554e5553e6d4418b4ca609ff6c3a"
	bobPublicKeyBytes, err := hex.DecodeString(bobPublicKeyHex)
	bobPublicKey := new(PublicKey)
	err = bobPublicKey.Unmarshal(bobPublicKeyBytes)
	require.NoError(t, err)

	// NIKE
	bobShared, err := GroupAction(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)

	aliceShared, err := GroupAction(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)

	bobSharedBytes, err := bobShared.Marshal()
	//_, err = bobShared.Marshal()
	require.NoError(t, err)

	aliceSharedBytes, err := aliceShared.Marshal()
	//_, err = aliceShared.Marshal()
	require.NoError(t, err)

	require.Equal(t, bobSharedBytes, aliceSharedBytes)
}
