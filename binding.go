package ctidh

// #include "binding.h"
// #include <csidh.h>
import "C"
import (
	"errors"
	"unsafe"
)

// ErrPublicKeyValidation indicates a public key validation failure.
var ErrPublicKeyValidation error = errors.New("CTIDH/cgo: public key validation failure")

// ErrCTIDH indicates a group action failure.
var ErrCTIDH error = errors.New("CTIDH/cgo: group action failure")

// PublicKey is a public CTIDH key.
type PublicKey struct {
	publicKey C.public_key
}

// Bytes returns the PublicKey as a byte slice.
func (p *PublicKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.publicKey.A.x.c), C.int(C.UINTBIG_LIMBS*8))
}

// FromBytes loads a PublicKey from the given byte slice.
func (p *PublicKey) FromBytes(data []byte) error {
	key := C.CBytes(data)
	defer C.free(key)
	publicKey := *((*C.public_key)(key))
	if !C.validate(&publicKey) {
		return ErrPublicKeyValidation
	}
	p.publicKey = publicKey
	return nil
}

// PrivateKey is a private CTIDH key.
type PrivateKey struct {
	privateKey C.private_key
}

// Marshal serializes PrivateKey into a byte slice.
func (p *PrivateKey) Marshal() ([]byte, error) {
	return C.GoBytes(unsafe.Pointer(&p.privateKey), C.primes_num), nil
}

// Unmarshal loads a PrivateKey from the given byte slice.
func (p *PrivateKey) Unmarshal(data []byte) error {
	key := C.CBytes(data)
	defer C.free(key)
	p.privateKey = *((*C.private_key)(key))
	return nil
}

// DerivePublicKey derives a public key given a private key.
func DerivePublicKey(privKey *PrivateKey) (*PublicKey, error) {
	var base C.public_key
	baseKey := new(PublicKey)
	baseKey.publicKey = base
	pubKey, err := groupAction(privKey, baseKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// GenerateKeyPair generates a new private and then
// attempts to compute the public key.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	privKey := new(PrivateKey)
	C.csidh_private(&privKey.privateKey)
	pubKey, err := DerivePublicKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func groupAction(privateKey *PrivateKey, publicKey *PublicKey) (*PublicKey, error) {
	sharedKey := new(PublicKey)
	ok := C.csidh(&sharedKey.publicKey, &publicKey.publicKey, &privateKey.privateKey)
	if !ok {
		return nil, ErrCTIDH
	}
	return sharedKey, nil
}

// DeriveSecret derives a shared secret.
func DeriveSecret(privateKey *PrivateKey, publicKey *PublicKey) (*PublicKey, error) {
	return groupAction()
}
