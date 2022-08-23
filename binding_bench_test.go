package ctidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkPublicKeySerializing(b *testing.B) {
	for n := 0; n < b.N; n++ {
		privKey, publicKey, err := GenerateKeyPair()
		require.NoError(b, err)

		publicKeyBytes := publicKey.Bytes()

		publicKey2 := new(PublicKey)
		err = publicKey2.FromBytes(publicKeyBytes)
		require.NoError(b, err)

		publicKey2Bytes := publicKey2.Bytes()

		publicKey3, err := DerivePublicKey(privKey)
		require.NoError(b, err)

		publicKey3Bytes := publicKey3.Bytes()

		require.Equal(b, publicKeyBytes, publicKey2Bytes)
		require.Equal(b, publicKey3Bytes, publicKeyBytes)
	}
}

func BenchmarkPrivateKeySerializing(b *testing.B) {
	for n := 0; n < b.N; n++ {
		privateKey, _, err := GenerateKeyPair()
		require.NoError(b, err)

		privateKeyBytes := privateKey.Bytes()

		privateKey2 := new(PrivateKey)
		privateKey2.FromBytes(privateKeyBytes)
		privateKey2Bytes := privateKey2.Bytes()

		require.Equal(b, privateKeyBytes, privateKey2Bytes)
	}
}

func BenchmarkNIKE(b *testing.B) {
	for n := 0; n < b.N; n++ {
		alicePrivate, alicePublic, err := GenerateKeyPair()
		require.NoError(b, err)

		bobPrivate, bobPublic, err := GenerateKeyPair()
		require.NoError(b, err)

		bobSharedBytes, err := DeriveSecret(bobPrivate, alicePublic)
		require.NoError(b, err)

		aliceSharedBytes, err := DeriveSecret(alicePrivate, bobPublic)
		require.NoError(b, err)

		require.Equal(b, bobSharedBytes, aliceSharedBytes)
	}
}

func BenchmarkDeriveSecret(b *testing.B) {
	alicePrivate, alicePublic, err := GenerateKeyPair()
	require.NoError(b, err)

	bobPrivate, bobPublic, err := GenerateKeyPair()
	require.NoError(b, err)

	var aliceSharedBytes []byte
	for n := 0; n < b.N; n++ {
		aliceSharedBytes, err = DeriveSecret(alicePrivate, bobPublic)
		require.NoError(b, err)
	}

	bobSharedBytes, err := DeriveSecret(bobPrivate, alicePublic)
	require.NoError(b, err)

	require.Equal(b, bobSharedBytes, aliceSharedBytes)
}
