package ctidh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKeyMarshaling(t *testing.T) {
	privKey, publicKey, err := GenerateKeyPair()
	require.NoError(t, err)

	publicKeyBytes, err := publicKey.Marshal()
	require.NoError(t, err)

	publicKey2 := new(PublicKey)
	err = publicKey2.Unmarshal(publicKeyBytes)
	require.NoError(t, err)

	publicKey2Bytes, err := publicKey2.Marshal()
	require.NoError(t, err)

	publicKey3, err := DerivePublicKey(privKey)
	require.NoError(t, err)

	publicKey3Bytes, err := publicKey3.Marshal()
	require.NoError(t, err)

	require.Equal(t, publicKeyBytes, publicKey2Bytes)
	require.Equal(t, publicKey3Bytes, publicKeyBytes)
}

func TestPrivateKeyMarshaling(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	require.NoError(t, err)

	privateKeyBytes, err := privateKey.Marshal()
	require.NoError(t, err)

	privateKey2 := new(PrivateKey)
	err = privateKey2.Unmarshal(privateKeyBytes)
	require.NoError(t, err)

	privateKey2Bytes, err := privateKey2.Marshal()
	require.NoError(t, err)

	require.Equal(t, privateKeyBytes, privateKey2Bytes)
}

func TestNIKE(t *testing.T) {
	alicePrivate, alicePublic, err := GenerateKeyPair()
	require.NoError(t, err)

	bobPrivate, bobPublic, err := GenerateKeyPair()
	require.NoError(t, err)

	bobShared, err := GroupAction(bobPrivate, alicePublic)
	require.NoError(t, err)

	aliceShared, err := GroupAction(alicePrivate, bobPublic)
	require.NoError(t, err)

	bobSharedBytes, err := bobShared.Marshal()
	require.NoError(t, err)

	aliceSharedBytes, err := aliceShared.Marshal()
	require.NoError(t, err)

	require.Equal(t, bobSharedBytes, aliceSharedBytes)
}
