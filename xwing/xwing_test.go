package xwing

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Seed  string `json:"seed"`
	Pk    string `json:"pk"`
	Eseed string `json:"eseed"`
	Ct    string `json:"ct"`
	Ss    string `json:"ss"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vs
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectorKeyGen checks seed expansion against every Appendix C vector.
func TestVectorKeyGen(t *testing.T) {
	for i, v := range loadVectors(t) {
		k, err := NewPrivateKey(mustHex(t, v.Seed))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(k.PublicKey(), mustHex(t, v.Pk)) {
			t.Fatalf("vector %d: derived public key does not match", i)
		}
	}
}

// TestVectorDecapsulate checks decapsulation of every Appendix C ciphertext.
func TestVectorDecapsulate(t *testing.T) {
	for i, v := range loadVectors(t) {
		k, err := NewPrivateKey(mustHex(t, v.Seed))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		ss, err := k.Decapsulate(mustHex(t, v.Ct))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(ss, mustHex(t, v.Ss)) {
			t.Fatalf("vector %d: shared secret does not match", i)
		}
	}
}

// TestVectorEncapsulateDerand reproduces EncapsulateDerand (draft section
// 5.4.1) using crypto/mlkem/mlkemtest for the ML-KEM half and eseed[32:64]
// as the X25519 ephemeral secret, then checks ct and ss byte for byte.
func TestVectorEncapsulateDerand(t *testing.T) {
	for i, v := range loadVectors(t) {
		pub := mustHex(t, v.Pk)
		eseed := mustHex(t, v.Eseed)

		ekM, err := mlkem.NewEncapsulationKey768(pub[:1184])
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		ssM, ctM, err := mlkemtest.Encapsulate768(ekM, eseed[:32])
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		ekX, err := ecdh.X25519().NewPrivateKey(eseed[32:64])
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		pkX, err := ecdh.X25519().NewPublicKey(pub[1184:])
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		ssX, err := ekX.ECDH(pkX)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		ctX := ekX.PublicKey().Bytes()
		ss := combiner(ssM, ssX, ctX, pub[1184:])
		ct := append(ctM, ctX...)

		if !bytes.Equal(ct, mustHex(t, v.Ct)) {
			t.Fatalf("vector %d: derandomized ciphertext does not match", i)
		}
		if !bytes.Equal(ss, mustHex(t, v.Ss)) {
			t.Fatalf("vector %d: derandomized shared secret does not match", i)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := Encapsulate(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("round trip shared secrets differ")
	}
	if len(ss1) != SharedSecretSize {
		t.Fatalf("shared secret is %d bytes", len(ss1))
	}

	rek, err := NewPrivateKey(k.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rek.PublicKey(), k.PublicKey()) {
		t.Fatal("seed does not re-derive the same public key")
	}
}

// TestTamperedCiphertext confirms that flipping any region of the ciphertext
// changes or rejects the shared secret (ML-KEM implicit rejection for the
// lattice half, a different ECDH output for the X25519 half).
func TestTamperedCiphertext(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ss, ct, err := Encapsulate(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, pos := range []int{0, 500, 1087, 1088, 1119} {
		tampered := append([]byte(nil), ct...)
		tampered[pos] ^= 0x01
		got, err := k.Decapsulate(tampered)
		if err == nil && bytes.Equal(got, ss) {
			t.Fatalf("tampering byte %d still produced the original shared secret", pos)
		}
	}
}
