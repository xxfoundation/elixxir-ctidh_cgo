package ctidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKeyReset(t *testing.T) {
	zeros := make([]byte, PublicKeySize)
	_, publicKey, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotEqual(t, publicKey.Bytes(), zeros)

	publicKey.Reset()
	require.Equal(t, publicKey.Bytes(), zeros)
}

func TestPrivateKeyReset(t *testing.T) {
	zeros := make([]byte, PrivateKeySize)
	privateKey, _, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotEqual(t, privateKey.Bytes(), zeros)

	privateKey.Reset()
	require.Equal(t, privateKey.Bytes(), zeros)
}

func TestPublicKeyMarshaling(t *testing.T) {
	privKey, publicKey, err := GenerateKeyPair()
	require.NoError(t, err)

	publicKeyBytes := publicKey.Bytes()

	publicKey2 := new(PublicKey)
	err = publicKey2.FromBytes(publicKeyBytes)
	require.NoError(t, err)

	publicKey2Bytes := publicKey2.Bytes()

	publicKey3, err := DerivePublicKey(privKey)
	require.NoError(t, err)

	publicKey3Bytes := publicKey3.Bytes()

	require.Equal(t, publicKeyBytes, publicKey2Bytes)
	require.Equal(t, publicKey3Bytes, publicKeyBytes)
}

func TestPrivateKeyBytesing(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	require.NoError(t, err)

	privateKeyBytes := privateKey.Bytes()

	privateKey2 := new(PrivateKey)
	privateKey2.FromBytes(privateKeyBytes)
	privateKey2Bytes := privateKey2.Bytes()

	require.Equal(t, privateKeyBytes, privateKey2Bytes)
}

func TestNIKE(t *testing.T) {
	alicePrivate, alicePublic, err := GenerateKeyPair()
	require.NoError(t, err)

	bobPrivate, bobPublic, err := GenerateKeyPair()
	require.NoError(t, err)

	bobSharedBytes, err := DeriveSecret(bobPrivate, alicePublic)
	require.NoError(t, err)

	aliceSharedBytes, err := DeriveSecret(alicePrivate, bobPublic)
	require.NoError(t, err)

	require.Equal(t, bobSharedBytes, aliceSharedBytes)
}
