//go:build bits511
// +build bits511

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test511BitVectors(t *testing.T) {
	// Alice
	alicePrivateKeyHex := "fd020202fb01ff020001fbffff0003020502ff020500fefefe02010501fb01fcfffc03010001000101fb000400fe000100fc030100000301fcfe0001ffff01ff00fe00ff000300ffff00"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "17f085e2f4ada10a3f0b15b0e3cff0e13ee915d3915dd779ae22c4664f067966c1ec2fae5fafb2af06222b8bdc3b7a649114ac5cc0dbd13cf35e4b5e61a74815"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "02ff0401fe02fdff00040001fbfafefd00000002fe02fcfeff00fe010303020004fe0105fc00fd00ff0001fd04fe0302feff000000fe00ff02fefefdfe00010000030000000002fe0201"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "839aa1c32d36bb9e75cdb5c5ea62aea6ee56b8521dfae8bbfde9a70895f8f381b5a36bf5a87c2a5cda8b498711add07f21deaed998d985f7f79578759e233c25"
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

	sharedSecretHex := "74cc3560ed96ca88ad111f2feb5002240bc3a389c1b768eb588e4c4432a9ed748a5341b68618ed49bb81b3554fb6a5bc41289513c5321faa9b8230611f50f311"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}

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
