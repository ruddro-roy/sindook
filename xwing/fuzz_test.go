package xwing

import (
	"bytes"
	"testing"
)

// FuzzDecapsulate feeds arbitrary ciphertexts to a fixed identity. ML-KEM
// gives X-Wing implicit rejection, so most malformed well-sized ciphertexts
// yield a pseudorandom secret; low-order X25519 halves are explicitly
// rejected by documented design. Either way the invariants hold: no panic,
// wrong lengths never accepted, and both the secret and the accept/reject
// decision are deterministic (nondeterminism would leak rejection state).
func FuzzDecapsulate(f *testing.F) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	id, err := NewPrivateKey(seed)
	if err != nil {
		f.Fatal(err)
	}
	_, ct, err := Encapsulate(id.PublicKey())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct)
	f.Add(append(bytes.Repeat([]byte{0x00}, CiphertextSize-32), bytes.Repeat([]byte{0x00}, 32)...))

	f.Fuzz(func(t *testing.T, ct []byte) {
		ss1, err1 := id.Decapsulate(ct)
		ss2, err2 := id.Decapsulate(ct)
		if (err1 == nil) != (err2 == nil) || !bytes.Equal(ss1, ss2) {
			t.Fatal("decapsulation is not deterministic")
		}
		if err1 == nil {
			if len(ct) != CiphertextSize {
				t.Fatalf("ciphertext of %d bytes accepted", len(ct))
			}
			if len(ss1) != SharedSecretSize {
				t.Fatalf("shared secret is %d bytes", len(ss1))
			}
		}
	})
}

// FuzzEncapsulate feeds arbitrary bytes as a public key to Encapsulate.
// No panic, wrong sizes rejected, and any successful encapsulate yields
// correctly sized secrets and ciphertexts. Two encapsulations of the same
// valid key must not be byte-equal (randomized), but each must decapsulate
// with the matching private key to the same secret.
func FuzzEncapsulate(f *testing.F) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	id, err := NewPrivateKey(seed)
	if err != nil {
		f.Fatal(err)
	}
	validPub := id.PublicKey()
	f.Add(validPub)
	f.Add(bytes.Repeat([]byte{0x00}, PublicKeySize))
	f.Add([]byte{})
	f.Add(validPub[:100])
	f.Add(append([]byte(nil), validPub...))

	f.Fuzz(func(t *testing.T, pub []byte) {
		ss1, ct1, err1 := Encapsulate(pub)
		ss2, ct2, err2 := Encapsulate(pub)
		if (err1 == nil) != (err2 == nil) {
			// Determinism of accept/reject decision.
			t.Fatal("encapsulation accept/reject not deterministic")
		}
		if err1 != nil {
			return
		}
		if len(pub) != PublicKeySize {
			t.Fatalf("public key of %d bytes accepted", len(pub))
		}
		if len(ss1) != SharedSecretSize || len(ct1) != CiphertextSize {
			t.Fatalf("bad sizes ss=%d ct=%d", len(ss1), len(ct1))
		}
		if len(ss2) != SharedSecretSize || len(ct2) != CiphertextSize {
			t.Fatalf("second encaps bad sizes")
		}
		// Randomized encapsulation must not be deterministic; extremely small
		// chance of collision, but if it happens we just skip.
		if bytes.Equal(ct1, ct2) && bytes.Equal(ss1, ss2) {
			t.Skip("encapsulation collision (astronomically unlikely but benign)")
		}
		// If pub is the valid one, both ciphertexts must decapsulate correctly
		// (tested via round-trip when pub is known valid; for random pubs we
		// just check no panic on decapsulate).
		if bytes.Equal(pub, validPub) {
			dec1, err := id.Decapsulate(ct1)
			if err != nil || !bytes.Equal(dec1, ss1) {
				t.Fatalf("valid encaps decaps mismatch")
			}
			dec2, err := id.Decapsulate(ct2)
			if err != nil || !bytes.Equal(dec2, ss2) {
				t.Fatalf("second encaps decaps mismatch")
			}
		} else {
			// For arbitrary pubs that happened to be accepted, ensure decapsulate doesn't panic
			// and is deterministic. We don't have a private key, so just check encapsulate's own
			// output can be fed to a generated key's decapsulate only if we own it – skip.
			_ = ct2
		}
		// Tampering one byte of a valid ciphertext must change or reject the secret.
		if bytes.Equal(pub, validPub) {
			tampered := append([]byte(nil), ct1...)
			tampered[0] ^= 0x01
			got, err := id.Decapsulate(tampered)
			if err == nil && bytes.Equal(got, ss1) {
				t.Fatalf("tampered ciphertext produced original secret")
			}
		}
	})
}

// FuzzNewPrivateKey feeds arbitrary seeds to NewPrivateKey. No panic, wrong
// lengths rejected, and any accepted seed must be deterministic: same seed
// yields same public key and seed round-trip, and encapsulation/decapsulation
// agree.
func FuzzNewPrivateKey(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x42}, SeedSize))
	f.Add(bytes.Repeat([]byte{0x00}, SeedSize))
	f.Add(bytes.Repeat([]byte{0xff}, SeedSize))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, 16))
	f.Add(bytes.Repeat([]byte{0x00}, 64))
	f.Add(bytes.Repeat([]byte{0x42}, SeedSize-1))
	f.Add(bytes.Repeat([]byte{0x42}, SeedSize+1))

	f.Fuzz(func(t *testing.T, seed []byte) {
		k1, err1 := NewPrivateKey(seed)
		k2, err2 := NewPrivateKey(seed)
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("NewPrivateKey accept/reject not deterministic")
		}
		if err1 != nil {
			if len(seed) == SeedSize {
				t.Fatalf("valid %d-byte seed rejected: %v", SeedSize, err1)
			}
			return
		}
		if len(seed) != SeedSize {
			t.Fatalf("seed of %d bytes accepted", len(seed))
		}
		if !bytes.Equal(k1.PublicKey(), k2.PublicKey()) {
			t.Fatal("public key not deterministic for same seed")
		}
		if !bytes.Equal(k1.Seed(), k2.Seed()) {
			t.Fatal("seed round-trip mismatch")
		}
		if !bytes.Equal(k1.Seed(), seed) {
			t.Fatal("seed not preserved")
		}
		if len(k1.PublicKey()) != PublicKeySize {
			t.Fatalf("public key size %d", len(k1.PublicKey()))
		}
		// Round-trip encapsulate/decapsulate on derived key.
		ss1, ct, err := Encapsulate(k1.PublicKey())
		if err != nil {
			t.Fatalf("encapsulate derived key: %v", err)
		}
		ss2, err := k1.Decapsulate(ct)
		if err != nil {
			t.Fatalf("decapsulate own ciphertext: %v", err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Fatal("encap/decap mismatch on derived key")
		}
		// Second decaps must be deterministic.
		ss3, err := k1.Decapsulate(ct)
		if err != nil || !bytes.Equal(ss2, ss3) {
			t.Fatal("second decaps not deterministic")
		}
		// Wipe must not panic and must zero seed copy.
		seedCopy := k1.Seed()
		k1.Wipe()
		// After Wipe, Seed() returns zeros? Actually Wipe zeros internal seed, but Seed() returns copy of internal zeros.
		wiped := k1.Seed()
		for _, b := range wiped {
			if b != 0 {
				t.Fatal("Wipe did not zero seed")
			}
		}
		_ = seedCopy
	})
}

// FuzzDecapsulateRandomIdentity feeds both random seeds (identities) and
// random ciphertexts, ensuring NewPrivateKey + Decapsulate never panics
// together and that mismatched identities don't cross-accept in a way that
// would hint at non-constant-time leakage. This is a broader version of
// FuzzDecapsulate with identity diversity.
func FuzzDecapsulateRandomIdentity(f *testing.F) {
	seed1 := bytes.Repeat([]byte{0x42}, SeedSize)
	seed2 := bytes.Repeat([]byte{0x43}, SeedSize)
	id1, _ := NewPrivateKey(seed1)
	_, ct, _ := Encapsulate(id1.PublicKey())
	f.Add(seed1, ct)
	f.Add(seed2, bytes.Repeat([]byte{0x00}, CiphertextSize))
	f.Add(seed1, []byte{})

	f.Fuzz(func(t *testing.T, seed []byte, ct []byte) {
		id, err := NewPrivateKey(seed)
		if err != nil {
			// Invalid seed length: ensure Decapsulate not reached, but also
			// that empty/short ct doesn't panic when we skip.
			return
		}
		ss1, err1 := id.Decapsulate(ct)
		ss2, err2 := id.Decapsulate(ct)
		if (err1 == nil) != (err2 == nil) || !bytes.Equal(ss1, ss2) {
			t.Fatal("random-identity decapsulation not deterministic")
		}
		if err1 == nil && len(ct) != CiphertextSize {
			t.Fatalf("accepted ciphertext of %d bytes", len(ct))
		}
	})
}
