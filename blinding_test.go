package ctidh

import (
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/stretchr/testify/require"
)

func TestBlindingOperation(t *testing.T) {
	_, alicePublic, err := GenerateKeyPair()
	require.NoError(t, err)

	hkdf := hkdf.New(sha256.New, alicePublic.Bytes(), []byte{}, []byte("yo whats up"))

	blindingFactor := make([]byte, PrivateKeySize)
	_, err = io.ReadFull(hkdf, blindingFactor)
	require.NoError(t, err)

	oldKey := alicePublic.Bytes()
	alicePublic.Blind(blindingFactor)
	newKey := alicePublic.Bytes()

	require.NotEqual(t, oldKey, newKey)
	require.Equal(t, len(oldKey), len(newKey))
}
