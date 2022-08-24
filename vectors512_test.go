//go:build bits512
// +build bits512

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test512BitVectorBlindingOperation(t *testing.T) {
	publicKeyHex := "928d8753b4749add1a24a1eb7f3654535cdc8137fadd54d548fd7870c2bafa7cbd02a605fa7567679a5a01914f8c8c411843ac5890fd34ba1e99f4f6bd9bf612"
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	require.NoError(t, err)
	publicKey := new(PublicKey)
	err = publicKey.FromBytes(publicKeyBytes)
	require.NoError(t, err)

	blindingFactorHex := "4972d672d1acd58c3f3a3e3ba6d928c90e7dc4c35455fb9bdb5022de7018afd7ec09a13c8ed1892c8dfedac81d2c32956446ca9b37630879f92060e10040ea6d11ff8a9ef128a4328810"
	blindingFactor, err := hex.DecodeString(blindingFactorHex)
	require.NoError(t, err)

	publicKey.Blind(blindingFactor)

	blindingOutputHex := "a34b8ccd7b4f97859f1a0d2962b31a083d363a7d671340471516bd36f58def0b0203f44af2a799028a17a8856e18a7b603190e1a63adc215c0ae53d21c45761c"
	blindingOutputBytes, err := hex.DecodeString(blindingOutputHex)
	require.NoError(t, err)

	require.Equal(t, blindingOutputBytes, publicKey.Bytes())
}

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
	bobSharedBytes := DeriveSecret(bobPrivateKey, alicePublicKey)
	aliceSharedBytes := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "24081588d4f3232f788e4e65db4870a223942ad272722a70577c26533c93adcd798cd166f26bfbafa6d6e428bf502a98e753a5a17ba2669869b2082f50266932"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}

func TestPython512BitVectors(t *testing.T) {

	// Alice
	alicePrivateKeyHex := "fcfbfd01f6090104fe09ff0502040000060100fcfefc06ff04060000ff03fe010300010307ff01040201020006020000fcfefd01fe0000fdf9fdff040104000201fe0001fd020201fe00"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "f0e3123870580f84f10e269a5150baaaf7058a6f0437cb8678c5ad6a0dddd3355c76435ae054a873e76bf5f8bc58ec29053d02162c7d3f309764443e2a3f0f38"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "02f90009ff06ff03fb0701010501fffafdffff070204fdfefc02fe04fc00060302fefeff01f9020002fffb0000fe02ff00f6030003ff01010105fbfffd01fffe0302fc000101fc000101"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "7369aaee2b543f17655fd57a78e03140b9a7fda3773651920c89fcd2aa9875dd633c3762f39fbda81961c70b0716974352ad5833564c6764ee082f17545b374d"
	bobPublicKeyBytes, err := hex.DecodeString(bobPublicKeyHex)
	bobPublicKey := new(PublicKey)
	err = bobPublicKey.FromBytes(bobPublicKeyBytes)
	require.NoError(t, err)

	// NIKE
	bobSharedBytes := DeriveSecret(bobPrivateKey, alicePublicKey)
	aliceSharedBytes := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "0d84960ea3c52ad6264a53915757d1ff8733629914577151140ae28bd28325bc31151ae3a1447e0d68aae42abcc63dae249072a8e729678ab73fd333b32a7a3d"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}
