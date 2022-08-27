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
	alicePublic.Blind(blindingFactor)
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

	value1 := Blind(blindingFactor, NewPublicKey(DeriveSecret(clientPrivateKey, mixPublicKey)))
	value2 := DeriveSecret(mixPrivateKey, Blind(blindingFactor, clientPublicKey))

	require.Equal(t, value1.Bytes(), value2)
}
