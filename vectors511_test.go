//go:build bits511
// +build bits511

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)


func TestPython511BitVectors(t *testing.T) {

	// Alice
	alicePrivateKeyHex := "ff01000503f801020003fffe0401fd000501fe030002fc03fffc00fc00000104fb00fe02040200000003feff0100ff0101000100fffe0302fffeff000301010100ff0100ffff00000100"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "27e65081c09f7dee63101e78309ef0ec892342435f04f237194d3fcef22fd850875fae3b7237d0d5952b9ab6351571967c6d0ba219158ee276192adc3a177713"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "040000fdfafeff0003fffffa01fdfe02fe03fffc00ffff00fb030201fefd02fd01fe010300fd0202020300020101000100fa03ff00000000fd00ff030201020000000103000001010100"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "1c025d14327ca5dcad356f5f96df318c1d04434c554b7e79fc9a9a0c15e1f9b81665d5db19d5c1417dd0c7a31160db09b117817bb297faed7a068fb491627920"
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

	sharedSecretHex := "5ecc8e5159cdb3bfac9281e183d9b3cbf2e289c28dee69f99b2fd840f141686fb133a3a40360a4e6056230a649be57b4e045b4c28c5558f80f57f85b43bbaf33"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}

