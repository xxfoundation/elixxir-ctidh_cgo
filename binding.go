package ctidh

// #include "binding.h"
// #include <csidh.h>
import "C"
import (
	"errors"
	"unsafe"
)

var base C.public_key

var PublicKeyValidationError error = errors.New("public key validation failure")
var CSIDHError error = errors.New("CSIDH failure")

// PublicKey is a public CTIDH key.
type PublicKey struct {
	public_key C.public_key
}

// Marshal serializes the PublicKey.
func (p *PublicKey) Marshal() ([]byte, error) {
	return C.GoBytes(unsafe.Pointer(&p.public_key.A.x.c), C.int(C.UINTBIG_LIMBS*8)), nil
}

// Unmarshal loads a PublicKey from the given byte slice.
func (p *PublicKey) Unmarshal(data []byte) error {
	key := C.CBytes(data)
	defer C.free(key)
	public_key := *((*C.public_key)(key))
	if !C.validate(&public_key) {
		return PublicKeyValidationError
	}
	p.public_key = public_key
	return nil
}

// PrivateKey is a private CTIDH key.
type PrivateKey struct {
	private_key C.private_key
}

// Marshal serializes PrivateKey into a byte slice.
func (p *PrivateKey) Marshal() ([]byte, error) {
	return C.GoBytes(unsafe.Pointer(&p.private_key), C.primes_num), nil
}

// Unmarshal loads a PrivateKey from the given byte slice.
func (p *PrivateKey) Unmarshal(data []byte) error {
	key := C.CBytes(data)
	defer C.free(key)
	private_key := *((*C.private_key)(key))
	p.private_key = private_key
	return nil
}

// DerivePublicKey derives a public key given a private key.
func DerivePublicKey(privKey *PrivateKey) (*PublicKey, error) {
	baseKey := new(PublicKey)
	baseKey.public_key = base
	pubKey, err := GroupAction(privKey, baseKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// GenerateKeyPair generates a new private and then
// attempts to compute the public key.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	privKey := new(PrivateKey)
	C.csidh_private(&privKey.private_key)
	pubKey, err := DerivePublicKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

// GroupAction performs the cyclic group computation
// which for example can be used to compute a shared secret or public key.
func GroupAction(privateKey *PrivateKey, publicKey *PublicKey) (*PublicKey, error) {
	sharedKey := new(PublicKey)
	ok := C.csidh(&sharedKey.public_key, &publicKey.public_key, &privateKey.private_key)
	if !ok {
		return nil, CSIDHError
	}
	return sharedKey, nil
}
