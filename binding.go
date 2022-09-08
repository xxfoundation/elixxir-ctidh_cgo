package ctidh

// #include "binding.h"
// #include <csidh.h>
import "C"
import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"unsafe"
)

var (
	// PublicKeySize is the size in bytes of the public key.
	PublicKeySize int

	// PrivateKeySize is the size in bytes of the private key.
	PrivateKeySize int

	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = fmt.Errorf("%s: blinding data size invalid", Name())

	// ErrPublicKeyValidation indicates a public key validation failure.
	ErrPublicKeyValidation error = fmt.Errorf("%s: public key validation failure", Name())

	// ErrPublicKeySize indicates the raw data is not the correct size for a public key.
	ErrPublicKeySize error = fmt.Errorf("%s: raw public key data size is wrong", Name())

	// ErrPrivateKeySize indicates the raw data is not the correct size for a private key.
	ErrPrivateKeySize error = fmt.Errorf("%s: raw private key data size is wrong", Name())

	// ErrCTIDH indicates a group action failure.
	ErrCTIDH error = fmt.Errorf("%s: group action failure", Name())
)

// ErrPEMKeyTypeMismatch returns an error indicating that we tried
// to decode a PEM file containing a differing key type than the one
// we expected.
func ErrPEMKeyTypeMismatch(pemFile, gotType, wantType string) error {
	return fmt.Errorf("%s: Attempted to decode a PEM file %s of type %s which differs from the type we want %s",
		Name(),
		pemFile,
		gotType,
		wantType)
}

// PublicKey is a public CTIDH key.
type PublicKey struct {
	publicKey C.public_key
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func NewEmptyPublicKey() *PublicKey {
	return new(PublicKey)
}

// NewPublicKey creates a new public key from
// the given key material or panics if the
// key data is not PublicKeySize.
func NewPublicKey(key []byte) *PublicKey {
	k := new(PublicKey)
	err := k.FromBytes(key)
	if err != nil {
		panic(err)
	}
	return k
}

// String returns a string identifying
// this type as a CTIDH public key.
func (p *PublicKey) String() string {
	return Name() + "_PublicKey"
}

// ToPEMFile writes out the PublicKey to a PEM file at path f.
func (p *PublicKey) ToPEMFile(f string) error {
	keyType := Name() + " PUBLIC KEY"

	zeros := make([]byte, PublicKeySize)
	if bytes.Equal(p.Bytes(), zeros) {
		return fmt.Errorf("%s: attemted to serialize scrubbed key", Name())
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: p.Bytes(),
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// FromPEMFile reads the PublicKey from a PEM file at path f.
func (p *PublicKey) FromPEMFile(f string) error {
	keyType := Name() + " PUBLIC KEY"

	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(buf)
	if blk == nil {
		return fmt.Errorf("%s: failed to decode PEM file %v", Name(), f)
	}
	if blk.Type != keyType {
		return ErrPEMKeyTypeMismatch(f, blk.Type, keyType)
	}
	return p.FromBytes(blk.Bytes)
}

// Reset resets the PublicKey to all zeros.
func (p *PublicKey) Reset() {
	zeros := make([]byte, PublicKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

// Bytes returns the PublicKey as a byte slice.
func (p *PublicKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.publicKey.A.x.c), C.int(C.UINTBIG_LIMBS*8))
}

// FromBytes loads a PublicKey from the given byte slice.
func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrPublicKeySize
	}

	p.publicKey = *((*C.public_key)(unsafe.Pointer(&data[0])))
	if !C.validate(&p.publicKey) {
		return ErrPublicKeyValidation
	}

	return nil
}

// Blind performs a blinding operation
// and mutates the public key.
func (p *PublicKey) Blind(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrBlindDataSizeInvalid
	}

	privKey := new(PrivateKey)
	err := privKey.FromBytes(data)
	if err != nil {
		return err
	}

	pubKey := groupAction(privKey, p)
	p.publicKey = pubKey.publicKey

	return nil
}

// PrivateKey is a private CTIDH key.
type PrivateKey struct {
	privateKey C.private_key
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func NewEmptyPrivateKey() *PrivateKey {
	return new(PrivateKey)
}

// String returns a string identifying
// this type as a CTIDH private key.
func (p *PrivateKey) String() string {
	return Name() + "_PrivateKey"
}

// Reset resets the PrivateKey to all zeros.
func (p *PrivateKey) Reset() {
	zeros := make([]byte, PrivateKeySize)
	err := p.FromBytes(zeros)
	if err != nil {
		panic(err)
	}
}

// Bytes serializes PrivateKey into a byte slice.
func (p *PrivateKey) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&p.privateKey), C.primes_num)
}

// FromBytes loads a PrivateKey from the given byte slice.
func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrPrivateKeySize
	}

	p.privateKey = *((*C.private_key)(unsafe.Pointer(&data[0])))
	return nil
}

// ToPEMFile writes out the PrivateKey to a PEM file at path f.
func (p *PrivateKey) ToPEMFile(f string) error {
	keyType := Name() + " PRIVATE KEY"

	zeros := make([]byte, PrivateKeySize)
	if bytes.Equal(p.Bytes(), zeros) {
		return fmt.Errorf("%s: attemted to serialize scrubbed key", Name())
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: p.Bytes(),
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// FromPEMFile reads the PrivateKey from a PEM file at path f.
func (p *PrivateKey) FromPEMFile(f string) error {
	keyType := Name() + " PRIVATE KEY"

	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(buf)
	if blk == nil {
		return fmt.Errorf("%s: failed to decode PEM file %v", Name(), f)
	}
	if blk.Type != keyType {
		return ErrPEMKeyTypeMismatch(f, blk.Type, keyType)
	}
	return p.FromBytes(blk.Bytes)
}

// DerivePublicKey derives a public key given a private key.
func DerivePublicKey(privKey *PrivateKey) *PublicKey {
	var base C.public_key
	baseKey := new(PublicKey)
	baseKey.publicKey = base
	return groupAction(privKey, baseKey)
}

// GenerateKeyPair generates a new private and then
// attempts to compute the public key.
func GenerateKeyPair() (*PrivateKey, *PublicKey) {
	privKey := new(PrivateKey)
	C.csidh_private(&privKey.privateKey)
	return privKey, DerivePublicKey(privKey)
}

func groupAction(privateKey *PrivateKey, publicKey *PublicKey) *PublicKey {
	sharedKey := new(PublicKey)
	ok := C.csidh(&sharedKey.publicKey, &publicKey.publicKey, &privateKey.privateKey)
	if !ok {
		panic(ErrCTIDH)
	}
	return sharedKey
}

// DeriveSecret derives a shared secret.
func DeriveSecret(privateKey *PrivateKey, publicKey *PublicKey) []byte {
	sharedSecret := groupAction(privateKey, publicKey)
	return sharedSecret.Bytes()
}

// Blind performs a blinding operation
// returning the blinded public key.
func Blind(blindingFactor []byte, publicKey *PublicKey) *PublicKey {
	privKey := new(PrivateKey)
	err := privKey.FromBytes(blindingFactor)
	if err != nil {
		panic(err)
	}
	return groupAction(privKey, publicKey)
}

// BlindBytes performs the blinding operation against the
// two byte slices which must be the correct lengths:
//
// * publicKeyBytes must be the size of a public key.
//
// * blindingFactor must be the size of a private key.
//
// See also PublicKey's Blind method.
func BlindBytes(publicKeyBytes, blindingFactor []byte) ([]byte, error) {
	if len(publicKeyBytes) != PublicKeySize {
		return nil, ErrBlindDataSizeInvalid
	}

	if len(blindingFactor) != PrivateKeySize {
		return nil, ErrBlindDataSizeInvalid
	}

	pubKey := new(PublicKey)
	err := pubKey.FromBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	pubKey.Blind(blindingFactor)
	return pubKey.Bytes(), nil
}

// Name returns the string naming of the current
// CTIDH that this binding is being used with;
// Valid values are:
//
// CTIDH-511, CTIDH-512, CTIDH-1024 and, CTIDH-2048.
func Name() string {
	return fmt.Sprintf("CTIDH-%d", C.BITS)
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

func init() {
	validateBitSize(C.BITS)
	PrivateKeySize = C.primes_num
	switch C.BITS {
	case 511:
		PublicKeySize = 64
	case 512:
		PublicKeySize = 64
	case 1024:
		PublicKeySize = 128
	case 2048:
		PublicKeySize = 256
	}
}
