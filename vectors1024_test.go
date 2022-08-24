//go:build bits1024
// +build bits1024

package ctidh

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test1024BitVectorBlindingOperation(t *testing.T) {
	publicKeyHex := "859070e07094657ae90acfa5e03c0342cb1909bf73cc1d0992ef48f533444bdc334846872333cbf17b0b3a763f64b4d5435c91742269d6dfcfe5347473b28f881045a55f3e10a7a7dd5a7192013a932d29703a1236eb1964563a9892ab19fffa3590a0f0a2e02a2205baf6af83d192822f24516fb311506f4cc18687a18c1e0c"
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	require.NoError(t, err)
	publicKey := new(PublicKey)
	err = publicKey.FromBytes(publicKeyBytes)
	require.NoError(t, err)

	blindingFactorHex := "82b843e2e941649c8e25aafde8e088e2c3406f8a1cd5803566e9204c2178bf68e7fa0febcc721ef527d514c4a79d29d549f59c876a69b18d3b7112f2b2b2b68b6acb0037a60c00981c7f6edfbaeccba1dc54df5dd85c96256b9649f3df3676dba7578163075b4fff7012c2fadb9bd03b3b9488b5577bab3918d1899b3cba0ff5b046"
	blindingFactor, err := hex.DecodeString(blindingFactorHex)
	require.NoError(t, err)

	publicKey.Blind(blindingFactor)

	blindingOutputHex := "b7f1fb4cba440e61d516d4cdb6a8b542c057b76eb4b277e0114a544c943756721ee2d09136b0ce97eb099961a6b383820cf7aebec2217b6f7cb7169aec7d00788b5bf549e274a743d496258b99f3cd36d176d253cc858719f0db4027959d2c8fd8f731c5101cba9198dabe11ebf3f67191bd8210b5a5fd9387ff5892d2565200"
	blindingOutputBytes, err := hex.DecodeString(blindingOutputHex)
	require.NoError(t, err)

	require.Equal(t, blindingOutputBytes, publicKey.Bytes())
}

func Test1024BitVectors(t *testing.T) {
	// Alice
	alicePrivateKeyHex := "fe0001010000fe0100fe00ff00fc0300ffffff0000ff0100000000ff01010200000201fe01000100ff0000fdff010001ffffff03fd0000000000feff000101ff000401000100000100040000010001ff00000001000100000101ffffff010001ff00ff00ffff0000fe000100000100ff0000000002ff0000fe0000010000ff000000"
	alicePrivateKeyBytes, err := hex.DecodeString(alicePrivateKeyHex)
	require.NoError(t, err)
	alicePrivateKey := new(PrivateKey)
	alicePrivateKey.FromBytes(alicePrivateKeyBytes)

	alicePublicKeyHex := "b962dadf244d6239ab74d808b0a88b2078b549bb03fab005ef6a97c1ee448bdc5a37892aaddf762e0157de5670320e8007398fb3eeab00a09fcbfe3caffb1fcebd03c38144e76b5d1dcd623871dbc6fe13470a23901dbadac77626fd05f891f18416a94123f9333ef1bdfb7570fa248f2567e33a8661c1411c42963b93e7a506"
	alicePublicKeyBytes, err := hex.DecodeString(alicePublicKeyHex)
	alicePublicKey := new(PublicKey)
	err = alicePublicKey.FromBytes(alicePublicKeyBytes)
	require.NoError(t, err)

	// Bob
	bobPrivateKeyHex := "ffff01fe0000ff000102010103000000ff02000102fe0000000100fffefeff00000000fd01fe00fefd0001000000fc00fe0000fe000102000100000002feff0001ff0001010100ff01ffff0000010102000000020100010003fffd0000fe000000ff00ff01000001fd0001ff0000000001010000ff0100ffff010100ff000000ff00"
	bobPrivateKeyBytes, err := hex.DecodeString(bobPrivateKeyHex)
	require.NoError(t, err)
	bobPrivateKey := new(PrivateKey)
	bobPrivateKey.FromBytes(bobPrivateKeyBytes)

	bobPublicKeyHex := "e859133b1bb959a4f17135cd337477141f81684317b30a7f14bad81a867df388477c2bf7a7af738618b568f323b91762f2282706875341b9343a3cd0450073783a91fc71edca8c8b30f9ec6379137c91ce33dcae9dc3c7fd1a951925e299bafdbff6a29dcdb9ae1207f7fb986b6b1087bf05b79c542dca25993c5a43ef7dc105"
	bobPublicKeyBytes, err := hex.DecodeString(bobPublicKeyHex)
	bobPublicKey := new(PublicKey)
	err = bobPublicKey.FromBytes(bobPublicKeyBytes)
	require.NoError(t, err)

	// NIKE
	bobSharedBytes := DeriveSecret(bobPrivateKey, alicePublicKey)
	aliceSharedBytes := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "411abafeca991f77b6f9263721ca3e2898031871e18d91b61c33c8664a9fc3fccf331729a9dd60465687e53c3d7649abfd4a3e32f4ea86e351535c9b281a76a74fa6b057d94403e55941de7e91432e2e85cc8f5b13fa28314a8dc8f09360e44c802bfc8b036451b26bc54200e133dde3976aa1f4885277a7692da9d38c09e301"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}

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
	bobSharedBytes := DeriveSecret(bobPrivateKey, alicePublicKey)
	aliceSharedBytes := DeriveSecret(alicePrivateKey, bobPublicKey)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)

	sharedSecretHex := "b5ab3b4d9cac68c451a43d1b499e190d462788362089ca5f3e4462c1502bb06cc820fe2e46c0f9ddaf8de6fcf8c0b4238e677497ebc6f5bb622a894c3c485c9e16142579392b6af434db46b146416aab5d5bd43c3d0f1bc55755f1af93d137d20540e65fc54e7b2b564dceec6484dc2b8bdd30db2b4ea7ba86adecfcb3e7ba08"
	sharedSecretBytes, err := hex.DecodeString(sharedSecretHex)
	require.NoError(t, err)

	require.Equal(t, sharedSecretBytes, aliceSharedBytes)
}
