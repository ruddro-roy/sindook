// Package interop cross-tests sindook's X-Wing implementation against
// independent implementations: Cloudflare's CIRCL and Filippo Valsorda's
// filippo.io/mlkem768/xwing. Every test proves byte agreement in both
// directions, so a divergence from the specification in any of the three
// implementations fails here.
package interop

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	filippoxwing "filippo.io/mlkem768/xwing"
	circlxwing "github.com/cloudflare/circl/kem/xwing"

	"github.com/ruddro-roy/sindook/xwing"
)

const crossRounds = 32

type vector struct {
	Seed  string `json:"seed"`
	Pk    string `json:"pk"`
	Eseed string `json:"eseed"`
	Ct    string `json:"ct"`
	Ss    string `json:"ss"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../xwing/testdata/vectors.json")
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

func randomSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, xwing.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return seed
}

// TestVectorsCIRCL runs the draft Appendix C vectors through CIRCL, proving
// both implementations target the same version of the scheme.
func TestVectorsCIRCL(t *testing.T) {
	for i, v := range loadVectors(t) {
		seed := mustHex(t, v.Seed)
		sk, pk := circlxwing.DeriveKeyPairPacked(seed)
		if !bytes.Equal(pk, mustHex(t, v.Pk)) {
			t.Fatalf("vector %d: CIRCL public key diverges from draft", i)
		}
		ss, ct, err := circlxwing.Encapsulate(pk, mustHex(t, v.Eseed))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(ct, mustHex(t, v.Ct)) || !bytes.Equal(ss, mustHex(t, v.Ss)) {
			t.Fatalf("vector %d: CIRCL encapsulation diverges from draft", i)
		}
		if got := circlxwing.Decapsulate(mustHex(t, v.Ct), sk); !bytes.Equal(got, mustHex(t, v.Ss)) {
			t.Fatalf("vector %d: CIRCL decapsulation diverges from draft", i)
		}
	}
}

// TestVectorsFilippo runs key derivation and decapsulation of the draft
// vectors through filippo.io/mlkem768/xwing, which exposes no derandomized
// encapsulation.
func TestVectorsFilippo(t *testing.T) {
	for i, v := range loadVectors(t) {
		dk, err := filippoxwing.NewKeyFromSeed(mustHex(t, v.Seed))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(dk.EncapsulationKey(), mustHex(t, v.Pk)) {
			t.Fatalf("vector %d: filippo public key diverges from draft", i)
		}
		ss, err := filippoxwing.Decapsulate(dk, mustHex(t, v.Ct))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(ss, mustHex(t, v.Ss)) {
			t.Fatalf("vector %d: filippo decapsulation diverges from draft", i)
		}
	}
}

// TestCrossCIRCL proves seed-for-seed key agreement and both encapsulation
// directions between sindook and CIRCL.
func TestCrossCIRCL(t *testing.T) {
	for i := 0; i < crossRounds; i++ {
		seed := randomSeed(t)
		ours, err := xwing.NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		theirSK, theirPK := circlxwing.DeriveKeyPairPacked(seed)
		if !bytes.Equal(ours.PublicKey(), theirPK) {
			t.Fatalf("round %d: public keys diverge for the same seed", i)
		}

		ss, ct, err := xwing.Encapsulate(theirPK)
		if err != nil {
			t.Fatal(err)
		}
		if got := circlxwing.Decapsulate(ct, theirSK); !bytes.Equal(got, ss) {
			t.Fatalf("round %d: sindook to CIRCL shared secret mismatch", i)
		}

		ss2, ct2, err := circlxwing.Encapsulate(ours.PublicKey(), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ours.Decapsulate(ct2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, ss2) {
			t.Fatalf("round %d: CIRCL to sindook shared secret mismatch", i)
		}
	}
}

// TestCrossFilippo does the same in both directions against
// filippo.io/mlkem768/xwing.
func TestCrossFilippo(t *testing.T) {
	for i := 0; i < crossRounds; i++ {
		seed := randomSeed(t)
		ours, err := xwing.NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := filippoxwing.NewKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours.PublicKey(), theirs.EncapsulationKey()) {
			t.Fatalf("round %d: public keys diverge for the same seed", i)
		}

		ss, ct, err := xwing.Encapsulate(theirs.EncapsulationKey())
		if err != nil {
			t.Fatal(err)
		}
		got, err := filippoxwing.Decapsulate(theirs, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, ss) {
			t.Fatalf("round %d: sindook to filippo shared secret mismatch", i)
		}

		ct2, ss2, err := filippoxwing.Encapsulate(ours.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		got2, err := ours.Decapsulate(ct2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got2, ss2) {
			t.Fatalf("round %d: filippo to sindook shared secret mismatch", i)
		}
	}
}
