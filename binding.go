package ctidh

/*
#include "binding.h"
#include <csidh.h>

extern ctidh_fillrandom fillrandom_custom;

void custom_gen_private(void* context, private_key *priv) {
  csidh_private_withrng((uintptr_t)context, priv, fillrandom_custom);
}

void fillrandom_custom(
  void *const outptr,
  const size_t outsz,
  const uintptr_t context)
{
  go_fillrandom((void*)context, outptr, outsz);
}
*/
import "C"
import (
	"bytes"
	"crypto/hmac"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
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
func ErrPEMKeyTypeMismatch(gotType, wantType string) error {
	return fmt.Errorf("%s: Attempted to decode a PEM bytes of type %s"+
		" which differs from the type we want %s",
		Name(),
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

// ToPEM writes out the PublicKey to a PEM block and returns it
func (p *PublicKey) ToPEM() (*pem.Block, error) {
	keyType := Name() + " PUBLIC KEY"

	zeros := make([]byte, PublicKeySize)
	if bytes.Equal(p.Bytes(), zeros) {
		return nil, fmt.Errorf("%s: attemted to serialize scrubbed key",
			Name())
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: p.Bytes(),
	}
	return blk, nil
}

// ToPEMFile writes out the PublicKey to a PEM file at path f.
func (p *PublicKey) ToPEMFile(f string) error {
	blk, err := p.ToPEM()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// FromPEM reads the PublicKey from a PEM encoded byte slice.
func (p *PublicKey) FromPEM(pemBytes []byte) error {
	keyType := Name() + " PUBLIC KEY"

	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return fmt.Errorf("%s: failed to decode PEM", Name())
	}
	if blk.Type != keyType {
		return ErrPEMKeyTypeMismatch(blk.Type, keyType)
	}
	return p.FromBytes(blk.Bytes)
}

// FromPEMFile reads the PublicKey from a PEM file at path f.
func (p *PublicKey) FromPEMFile(f string) error {
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	err = p.FromPEM(buf)
	if err != nil {
		return fmt.Errorf("%s in file %s", err.Error(), f)
	}
	return nil
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

// Equal is a constant time comparison of the two public keys.
func (p *PublicKey) Equal(publicKey *PublicKey) bool {
	return hmac.Equal(p.Bytes(), publicKey.Bytes())
}

// Blind performs a blinding operation
// and mutates the public key.
// See notes below about blinding operation with CTIDH.
func (p *PublicKey) Blind(blindingFactor []byte) error {
	if len(blindingFactor) != PrivateKeySize {
		return ErrBlindDataSizeInvalid
	}
	var err error
	blinded, err := Blind(blindingFactor, p)
	if err != nil {
		panic(err)
	}
	p.publicKey = blinded.publicKey
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

// Equal is a constant time comparison of the two private keys.
func (p *PrivateKey) Equal(privateKey *PrivateKey) bool {
	return hmac.Equal(p.Bytes(), privateKey.Bytes())
}

// ToPEM writes out the PrivateKey to a PEM block.
func (p *PrivateKey) ToPEM() (*pem.Block, error) {
	keyType := Name() + " PRIVATE KEY"

	zeros := make([]byte, PrivateKeySize)
	if bytes.Equal(p.Bytes(), zeros) {
		return nil, fmt.Errorf("%s: attemted to serialize scrubbed key",
			Name())
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: p.Bytes(),
	}
	return blk, nil
}

// ToPEMFile writes out the PrivateKey to a PEM file at path f.
func (p *PrivateKey) ToPEMFile(f string) error {
	blk, err := p.ToPEM()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// FromPEM reads the PrivateKey from a PEM byte slice.
func (p *PrivateKey) FromPEM(pemBytes []byte) error {
	keyType := Name() + " PRIVATE KEY"

	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return fmt.Errorf("%s: failed to decode PEM bytes", Name())
	}
	if blk.Type != keyType {
		return ErrPEMKeyTypeMismatch(blk.Type, keyType)
	}
	return p.FromBytes(blk.Bytes)
}

// FromPEMFile reads the PrivateKey from a PEM file at path f.
func (p *PrivateKey) FromPEMFile(f string) error {
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	err = p.FromPEM(buf)
	if err != nil {
		return fmt.Errorf("%s in file %s", err.Error(), f)
	}
	return nil
}

// PublicKey returns the public key associated
// with the given private key.
func (p *PrivateKey) PublicKey() *PublicKey {
	return DerivePublicKey(p)
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

//export go_fillrandom
func go_fillrandom(context unsafe.Pointer, outptr unsafe.Pointer, outsz C.size_t) {
	rng := gopointer.Restore(context).(io.Reader)
	buf := make([]byte, outsz)
	count, err := rng.Read(buf)
	if err != nil {
		panic(err)
	}
	if count != int(outsz) {
		panic("rng fail")
	}
	p := uintptr(outptr)
	for i := 0; i < int(outsz); i++ {
		(*(*uint8)(unsafe.Pointer(p))) = uint8(buf[i])
		p += 1
	}
}

// GenerateKeyPairWithRNG uses the given RNG to derive a new keypair.
func GenerateKeyPairWithRNG(rng io.Reader) (*PrivateKey, *PublicKey) {
	privKey := &PrivateKey{}
	p := gopointer.Save(rng)
	C.custom_gen_private(p, &privKey.privateKey)
	gopointer.Unref(p)
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

// Blind performs a blinding operation returning the blinded public key.
//
// WARNING:
// Currently this blinding operation is not performed correctly
// because the blindingFactor is not a valid CTIDH private key.
// In order to fix this we need to be able to use the blinding
// factor as a seed for deterministically generating the CTIDH private key
// which participates in the group action operation.
// This will require a change to the high-ctidh library.
func Blind(blindingFactor []byte, publicKey *PublicKey) (*PublicKey, error) {
	if len(blindingFactor) != PrivateKeySize {
		return nil, ErrBlindDataSizeInvalid
	}

	privKey := new(PrivateKey)
	err := privKey.FromBytes(blindingFactor)
	if err != nil {
		return nil, err
	}
	return groupAction(privKey, publicKey), nil
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
