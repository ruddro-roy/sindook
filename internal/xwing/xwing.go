// Package xwing implements the X-Wing hybrid key encapsulation mechanism
// (X25519 + ML-KEM-768) as specified in draft-connolly-cfrg-xwing-kem-10.
// ML-KEM, X25519, SHAKE-256, and SHA3-256 all come from the Go standard
// library; this package contains only the key expansion, the combiner, and
// the concatenation layout defined by the draft.
package xwing

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
)

const (
	SeedSize         = 32
	PublicKeySize    = 1184 + 32
	CiphertextSize   = 1088 + 32
	SharedSecretSize = 32
)

// xwingLabel is the 6-byte domain separator from draft section 5.3 (hex 5c2e2f2f5e5c).
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// PrivateKey is an expanded X-Wing decapsulation key. The 32-byte seed is
// the canonical secret; everything else is derived from it.
type PrivateKey struct {
	seed [SeedSize]byte
	dkM  *mlkem.DecapsulationKey768
	skX  *ecdh.PrivateKey
	pub  []byte
}

// NewPrivateKey expands a 32-byte seed per expandDecapsulationKey (draft section 5.2).
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("xwing: seed must be 32 bytes")
	}
	expanded := sha3.SumSHAKE256(seed, 96)
	dkM, err := mlkem.NewDecapsulationKey768(expanded[0:64])
	if err != nil {
		return nil, err
	}
	skX, err := ecdh.X25519().NewPrivateKey(expanded[64:96])
	if err != nil {
		return nil, err
	}
	k := &PrivateKey{dkM: dkM, skX: skX}
	copy(k.seed[:], seed)
	k.pub = append(dkM.EncapsulationKey().Bytes(), skX.PublicKey().Bytes()...)
	return k, nil
}

// GenerateKey creates a private key from 32 bytes of system randomness.
func GenerateKey() (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewPrivateKey(seed)
}

// Seed returns a copy of the 32-byte secret seed.
func (k *PrivateKey) Seed() []byte {
	return append([]byte(nil), k.seed[:]...)
}

// PublicKey returns a copy of the 1216-byte encapsulation key (pk_M || pk_X).
func (k *PrivateKey) PublicKey() []byte {
	return append([]byte(nil), k.pub...)
}

func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(xwingLabel)
	return h.Sum(nil)
}

// Encapsulate derives a fresh 32-byte shared secret and 1120-byte ciphertext
// for the given public key (draft section 5.4).
func Encapsulate(pub []byte) (ss, ct []byte, err error) {
	if len(pub) != PublicKeySize {
		return nil, nil, errors.New("xwing: public key must be 1216 bytes")
	}
	ekM, err := mlkem.NewEncapsulationKey768(pub[:1184])
	if err != nil {
		return nil, nil, err
	}
	pkX, err := ecdh.X25519().NewPublicKey(pub[1184:])
	if err != nil {
		return nil, nil, err
	}
	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ssX, err := ekX.ECDH(pkX)
	if err != nil {
		return nil, nil, err
	}
	ssM, ctM := ekM.Encapsulate()
	ctX := ekX.PublicKey().Bytes()
	ss = combiner(ssM, ssX, ctX, pub[1184:])
	ct = append(ctM, ctX...)
	if len(ct) != CiphertextSize {
		return nil, nil, errors.New("xwing: internal ciphertext length mismatch")
	}
	return ss, ct, nil
}

// Decapsulate recovers the shared secret (draft section 5.5). Unlike the
// draft's plain X25519, crypto/ecdh rejects low-order points by erroring on
// an all-zero X25519 output; such ciphertexts are treated as invalid here,
// which only rejects values no honest sealer produces.
func (k *PrivateKey) Decapsulate(ct []byte) ([]byte, error) {
	if len(ct) != CiphertextSize {
		return nil, errors.New("xwing: ciphertext must be 1120 bytes")
	}
	ssM, err := k.dkM.Decapsulate(ct[:1088])
	if err != nil {
		return nil, err
	}
	ctX, err := ecdh.X25519().NewPublicKey(ct[1088:])
	if err != nil {
		return nil, err
	}
	ssX, err := k.skX.ECDH(ctX)
	if err != nil {
		return nil, err
	}
	return combiner(ssM, ssX, ctX.Bytes(), k.pub[1184:]), nil
}
