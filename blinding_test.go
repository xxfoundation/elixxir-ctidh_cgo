package ctidh

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimpleBlindingOperation(t *testing.T) {
	_, alicePublic := GenerateKeyPair()

	blindingFactor := make([]byte, PrivateKeySize)
	_, err := rand.Read(blindingFactor)
	require.NoError(t, err)

	oldKey := alicePublic.Bytes()
	err = alicePublic.Blind(blindingFactor)
	require.NoError(t, err)
	newKey := alicePublic.Bytes()

	require.NotEqual(t, oldKey, newKey)
	require.Equal(t, len(oldKey), len(newKey))
}

func TestBlindingOperation(t *testing.T) {
	mixPrivateKey, mixPublicKey := GenerateKeyPair()
	clientPrivateKey, clientPublicKey := GenerateKeyPair()

	blindingFactor := make([]byte, PrivateKeySize)
	_, err := rand.Read(blindingFactor)
	require.NoError(t, err)

	value1, err := Blind(blindingFactor, NewPublicKey(DeriveSecret(clientPrivateKey, mixPublicKey)))
	require.NoError(t, err)
	blinded, err := Blind(blindingFactor, clientPublicKey)
	require.NoError(t, err)
	value2 := DeriveSecret(mixPrivateKey, blinded)

	require.Equal(t, value1.Bytes(), value2)
}
