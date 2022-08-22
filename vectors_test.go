//go:build bits512
// +build bits512

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test512BitVectors(t *testing.T) {

	// Alice
	alicePrivateKeyHex := "0500ff0500fbfc04020a04010001050701ff01fcfc00fbff00fd010601fc00fffefd01f901f700fe000401ff0306fdff000102ff000204fdfd02ff01fc0000010401fd0000fffeff0500"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "a9f14cf61e8c8b9bf701c704ed66324ec3813eb7869106d636e4f72b09ac07e44979d45634f616ae12d876aec0de546f21cd9219d47e07da0929ec456d939338"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "06fc0009fc01ff0201060304fcf501010004020104fd02fff8fefffc0103030100ffff040304ff0102fa0002ff000101fafdfe03ff0400fe01fa00fd0101ff03fe020101030200ff0001"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "1e4a6a12ae0218f3eda0213d28e640bf4e39a56847b0374576cb02a18219d7c64ea7e87414ce20eb45566f6cf6243e8fb6f4554e5553e6d4418b4ca609ff6c3a"
	bobPublicKeyBytes, err := hex.DecodeString(bobPublicKeyHex)
	bobPublicKey := new(PublicKey)
	err = bobPublicKey.FromBytes(bobPublicKeyBytes)
	require.NoError(t, err)

	// NIKE
	bobShared, err := DeriveSecret(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)

	aliceShared, err := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)

	bobSharedBytes := bobShared.Bytes()
	aliceSharedBytes := aliceShared.Bytes()
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "24081588d4f3232f788e4e65db4870a223942ad272722a70577c26533c93adcd798cd166f26bfbafa6d6e428bf502a98e753a5a17ba2669869b2082f50266932"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}
