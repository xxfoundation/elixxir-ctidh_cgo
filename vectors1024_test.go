//go:build bits1024
// +build bits1024

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPython1024BitVectors(t *testing.T) {

	// Alice
	alicePrivateKeyHex := "000200fffd0000ff03fffe0200010000fd00ff0000fffd010001fe01000001ff00ff020100fe00fffd010100000101feff0100010101fd000000000000fefffffe02000101020000ff0101020000ffffff00000002000001020101ff00ff0200ffff0000000100000000000001ffff00000100fd000000010000fe00ffff00000000"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "f364c4b220d57528d6b64432e93fb40495177faf9a224955f34b5700cf1cf35be7c476e43681a375602fc57eba16aa0c5c4ae02f3031d55d84c2cb679969074216ca0f114d7c798dc12c65b9820d2dce650070c79f992f34c6653963d62fba82a9f48293940ec6001093a06023ee0b80022d19e33d3a669934cbd289c87ddb01"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "00fe00fe0101000200fe0002000100fe01000001020200000100ff040000ff000003010002000001010000fc0100010200fe00010000fe000000fe00000201ff000202ffff000000ff00ff0002ff0101fe010000000101ff0001fe00000001000000ff00ff020100000000ff00ffff0000ff00000000ffff0003ff000100ff000000"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "90d51cc0f48b0ce2712bc8305e7415300bde7feef634e17211ae493ea57b56d1ad81914e85e3b8b43275e7a31c9d440f3f88ef476a31c7e504520f7b538bcbe80fd3bbbc76726c4c37c6c8f9f857618602fcbbc6899e8ac420de32e1ebb1f1178dd13f600afba82276b5f5e6b40dc421b5c3b1f342a9152009b1fae95d372303"
	bobPublicKeyBytes, err := hex.DecodeString(bobPublicKeyHex)
	bobPublicKey := new(PublicKey)
	err = bobPublicKey.FromBytes(bobPublicKeyBytes)
	require.NoError(t, err)

	// NIKE
	bobSharedBytes, err := DeriveSecret(bobPrivateKey, alicePublicKey)
	require.NoError(t, err)

	aliceSharedBytes, err := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.NoError(t, err)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "b5ab3b4d9cac68c451a43d1b499e190d462788362089ca5f3e4462c1502bb06cc820fe2e46c0f9ddaf8de6fcf8c0b4238e677497ebc6f5bb622a894c3c485c9e16142579392b6af434db46b146416aab5d5bd43c3d0f1bc55755f1af93d137d20540e65fc54e7b2b564dceec6484dc2b8bdd30db2b4ea7ba86adecfcb3e7ba08"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}
