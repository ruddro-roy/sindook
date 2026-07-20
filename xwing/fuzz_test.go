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
