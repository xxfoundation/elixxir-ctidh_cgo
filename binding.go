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

// ErrPublicKeySize indicates the raw data is not the correct size for a public key.
var ErrPublicKeySize error = errors.New("CTIDH/cgo: raw public key data size is wrong")

// ErrPrivateKeySize indicates the raw data is not the correct size for a private key.
var ErrPrivateKeySize error = errors.New("CTIDH/cgo: raw private key data size is wrong")

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

func validateBitSize(bits int) {
	switch bits {
	case 511:
	case 512:
	case 1024:
	case 2048:
	default:
		panic("CTIDH/cgo: BITS must be 511 or 512 or 1024 or 2048")
	}
}

// FromBytes loads a PublicKey from the given byte slice.
func (p *PublicKey) FromBytes(data []byte) error {
	validateBitSize(C.BITS)

	if len(data) != C.BITS/8 {
		return ErrPublicKeySize
	}

	p.publicKey = *((*C.public_key)(unsafe.Pointer(&data[0])))
	if !C.validate(&p.publicKey) {
		return ErrPublicKeyValidation
	}

	return nil
}

// PrivateKey is a private CTIDH key.
type PrivateKey struct {
	privateKey C.private_key
}

// Bytes serializes PrivateKey into a byte slice.
func (p *PrivateKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.privateKey), C.primes_num)
}

// FromBytes loads a PrivateKey from the given byte slice.
func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != C.primes_num {
		return ErrPrivateKeySize
	}

	p.privateKey = *((*C.private_key)(unsafe.Pointer(&data[0])))
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
func DeriveSecret(privateKey *PrivateKey, publicKey *PublicKey) ([]byte, error) {
	sharedSecret, err := groupAction(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret.Bytes(), nil
}
