package ctidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkPublicKeySerializing(b *testing.B) {
	for n := 0; n < b.N; n++ {
		privKey, publicKey := GenerateKeyPair()

		publicKeyBytes := publicKey.Bytes()

		publicKey2 := new(PublicKey)
		err := publicKey2.FromBytes(publicKeyBytes)
		require.NoError(b, err)

		publicKey2Bytes := publicKey2.Bytes()
		publicKey3 := DerivePublicKey(privKey)
		publicKey3Bytes := publicKey3.Bytes()

		require.Equal(b, publicKeyBytes, publicKey2Bytes)
		require.Equal(b, publicKey3Bytes, publicKeyBytes)
	}
}

func BenchmarkPrivateKeySerializing(b *testing.B) {
	for n := 0; n < b.N; n++ {
		privateKey, _ := GenerateKeyPair()
		privateKeyBytes := privateKey.Bytes()

		privateKey2 := new(PrivateKey)
		privateKey2.FromBytes(privateKeyBytes)
		privateKey2Bytes := privateKey2.Bytes()

		require.Equal(b, privateKeyBytes, privateKey2Bytes)
	}
}

func BenchmarkNIKE(b *testing.B) {
	for n := 0; n < b.N; n++ {
		alicePrivate, alicePublic := GenerateKeyPair()
		bobPrivate, bobPublic := GenerateKeyPair()

		bobSharedBytes := DeriveSecret(bobPrivate, alicePublic)
		aliceSharedBytes := DeriveSecret(alicePrivate, bobPublic)

		require.Equal(b, bobSharedBytes, aliceSharedBytes)
	}
}

func BenchmarkDeriveSecret(b *testing.B) {
	alicePrivate, alicePublic := GenerateKeyPair()
	bobPrivate, bobPublic := GenerateKeyPair()

	var aliceSharedBytes []byte
	for n := 0; n < b.N; n++ {
		aliceSharedBytes = DeriveSecret(alicePrivate, bobPublic)
	}

	bobSharedBytes := DeriveSecret(bobPrivate, alicePublic)
	require.Equal(b, bobSharedBytes, aliceSharedBytes)
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = GenerateKeyPair()
	}
}
