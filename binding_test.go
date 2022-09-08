package ctidh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateKeyPEMSerialization(t *testing.T) {
	privateKey, _ := GenerateKeyPair()

	tmpdir := os.TempDir()

	privateKeyPemFile := "private_key.pem"
	pemFile := filepath.Join(tmpdir, privateKeyPemFile)
	err := privateKey.ToPEMFile(pemFile)
	require.NoError(t, err)

	privateKey2 := NewEmptyPrivateKey()
	err = privateKey2.FromPEMFile(pemFile)
	require.NoError(t, err)

	require.Equal(t, privateKey.Bytes(), privateKey2.Bytes())
}

func TestPublicKeyPEMSerialization(t *testing.T) {
	_, publicKey := GenerateKeyPair()

	tmpdir := os.TempDir()

	publicKeyPemFile := "public_key.pem"
	pemFile := filepath.Join(tmpdir, publicKeyPemFile)
	err := publicKey.ToPEMFile(pemFile)
	require.NoError(t, err)

	publicKey2 := NewEmptyPublicKey()
	err = publicKey2.FromPEMFile(pemFile)
	require.NoError(t, err)

	require.Equal(t, publicKey.Bytes(), publicKey2.Bytes())
}

func TestPublicKeyReset(t *testing.T) {
	zeros := make([]byte, PublicKeySize)
	_, publicKey := GenerateKeyPair()
	require.NotEqual(t, publicKey.Bytes(), zeros)

	publicKey.Reset()
	require.Equal(t, publicKey.Bytes(), zeros)
}

func TestPrivateKeyReset(t *testing.T) {
	zeros := make([]byte, PrivateKeySize)
	privateKey, _ := GenerateKeyPair()
	require.NotEqual(t, privateKey.Bytes(), zeros)

	privateKey.Reset()
	require.Equal(t, privateKey.Bytes(), zeros)
}

func TestPublicKeyMarshaling(t *testing.T) {
	privKey, publicKey := GenerateKeyPair()
	publicKeyBytes := publicKey.Bytes()

	publicKey2 := new(PublicKey)
	err := publicKey2.FromBytes(publicKeyBytes)
	require.NoError(t, err)

	publicKey2Bytes := publicKey2.Bytes()

	publicKey3 := DerivePublicKey(privKey)
	publicKey3Bytes := publicKey3.Bytes()

	require.Equal(t, publicKeyBytes, publicKey2Bytes)
	require.Equal(t, publicKey3Bytes, publicKeyBytes)
}

func TestPrivateKeyBytesing(t *testing.T) {
	privateKey, _ := GenerateKeyPair()
	privateKeyBytes := privateKey.Bytes()

	privateKey2 := new(PrivateKey)
	privateKey2.FromBytes(privateKeyBytes)
	privateKey2Bytes := privateKey2.Bytes()

	require.Equal(t, privateKeyBytes, privateKey2Bytes)
}

func TestNIKE(t *testing.T) {
	alicePrivate, alicePublic := GenerateKeyPair()
	bobPrivate, bobPublic := GenerateKeyPair()
	bobSharedBytes := DeriveSecret(bobPrivate, alicePublic)
	aliceSharedBytes := DeriveSecret(alicePrivate, bobPublic)
	require.Equal(t, bobSharedBytes, aliceSharedBytes)
}
