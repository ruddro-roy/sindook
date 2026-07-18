package box

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

// Small parameters keep the Argon2id tests fast; validity is still enforced.
var testArgon = Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}

// Header sizes of v2 files with a single slot, per docs/FORMAT.md.
const (
	v2PassHeader  = 25 + 3 + passSlotBody + macSize
	v2XWingHeader = 25 + 3 + xwingSlotBody + macSize
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newIdentity(t *testing.T) *xwing.PrivateKey {
	t.Helper()
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealTo(t *testing.T, plain []byte, opts SealOptions) []byte {
	t.Helper()
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(plain), opts); err != nil {
		t.Fatal(err)
	}
	return sealed.Bytes()
}

func openWith(t *testing.T, blob []byte, id *xwing.PrivateKey, pass []byte) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := Open(&out, bytes.NewReader(blob), id, pass)
	return out.Bytes(), err
}

func roundTripSizes() []int {
	return []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 2*chunkSize + 513}
}

func TestRecipientRoundTrip(t *testing.T) {
	k := newIdentity(t)
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		out, err := openWith(t, sealTo(t, plain, SealOptions{Recipients: [][]byte{k.PublicKey()}}), k, nil)
		if err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		blob := sealTo(t, plain, SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})
		out, err := openWith(t, blob, nil, pass)
		if err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestMultiRecipient(t *testing.T) {
	k1, k2, k3, stranger := newIdentity(t), newIdentity(t), newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300)
	blob := sealTo(t, plain, SealOptions{
		Recipients: [][]byte{k1.PublicKey(), k2.PublicKey(), k3.PublicKey()},
	})
	for i, k := range []*xwing.PrivateKey{k1, k2, k3} {
		out, err := openWith(t, blob, k, nil)
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("recipient %d: plaintext mismatch", i)
		}
	}
	if _, err := openWith(t, blob, stranger, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("stranger: got %v, want ErrWrongKey", err)
	}
}

func TestMixedSlots(t *testing.T) {
	k := newIdentity(t)
	plain := randomBytes(t, 300)
	blob := sealTo(t, plain, SealOptions{
		Recipients:  [][]byte{k.PublicKey()},
		Passphrases: [][]byte{[]byte("rescue")},
		Argon:       testArgon,
	})
	if out, err := openWith(t, blob, k, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("identity path: %v", err)
	}
	if out, err := openWith(t, blob, nil, []byte("rescue")); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("passphrase path: %v", err)
	}
}

func TestV1Fixtures(t *testing.T) {
	seed, err := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	if err != nil {
		t.Fatal(err)
	}
	id, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("sindook v1 golden fixture\n")

	rec, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := openWith(t, rec, id, nil); err != nil || !bytes.Equal(out, want) {
		t.Fatalf("v1 recipient fixture: %v", err)
	}

	pw, err := os.ReadFile("testdata/v1-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := openWith(t, pw, nil, []byte("golden")); err != nil || !bytes.Equal(out, want) {
		t.Fatalf("v1 passphrase fixture: %v", err)
	}
}

func TestRewrapFast(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 2*chunkSize+513)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	var rewrapped bytes.Buffer
	err := Rewrap(&rewrapped, bytes.NewReader(old), k1, nil,
		SealOptions{Recipients: [][]byte{k2.PublicKey()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	blob := rewrapped.Bytes()

	if out, err := openWith(t, blob, k2, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("new recipient: %v", err)
	}
	if _, err := openWith(t, blob, k1, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("removed recipient: got %v, want ErrWrongKey", err)
	}
	// Fast mode must carry payload bytes over verbatim.
	if !bytes.Equal(old[v2XWingHeader:], blob[v2XWingHeader:]) {
		t.Fatal("fast rewrap modified payload bytes")
	}
}

func TestRewrapFastUpgradesV1(t *testing.T) {
	seed, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	oldID, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	newID := newIdentity(t)
	v1, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}

	var upgraded bytes.Buffer
	err = Rewrap(&upgraded, bytes.NewReader(v1), oldID, nil,
		SealOptions{Recipients: [][]byte{newID.PublicKey()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(upgraded.Bytes(), []byte(magicV2)) {
		t.Fatal("upgraded file is not format v2")
	}
	out, err := openWith(t, upgraded.Bytes(), newID, nil)
	if err != nil || !bytes.Equal(out, []byte("sindook v1 golden fixture\n")) {
		t.Fatalf("upgraded v1 file: %v", err)
	}
}

func TestRewrapDeep(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 2*chunkSize+513)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	var rewrapped bytes.Buffer
	err := Rewrap(&rewrapped, bytes.NewReader(old), k1, nil,
		SealOptions{Recipients: [][]byte{k2.PublicKey()}}, true)
	if err != nil {
		t.Fatal(err)
	}
	blob := rewrapped.Bytes()

	if out, err := openWith(t, blob, k2, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("deep rewrap open: %v", err)
	}
	if bytes.Equal(old[v2XWingHeader:], blob[v2XWingHeader:]) {
		t.Fatal("deep rewrap left payload bytes unchanged")
	}
}

func TestSlotStripping(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	blob := sealTo(t, randomBytes(t, 100), SealOptions{
		Recipients: [][]byte{k1.PublicKey(), k2.PublicKey()},
	})
	// Rebuild the file with the second slot removed and the count patched.
	slotLen := 3 + xwingSlotBody
	stripped := append([]byte(nil), blob[:25+slotLen]...)
	stripped[24] = 1
	stripped = append(stripped, blob[25+2*slotLen:]...)

	if _, err := openWith(t, stripped, k1, nil); !errors.Is(err, ErrHeaderTampered) {
		t.Fatalf("got %v, want ErrHeaderTampered", err)
	}
}

func TestWrongIdentity(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	blob := sealTo(t, []byte("secret"), SealOptions{Recipients: [][]byte{k1.PublicKey()}})
	if _, err := openWith(t, blob, k2, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	blob := sealTo(t, []byte("secret"), SealOptions{Passphrases: [][]byte{[]byte("right")}, Argon: testArgon})
	if _, err := openWith(t, blob, nil, []byte("wrong")); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestModeErrors(t *testing.T) {
	k := newIdentity(t)
	rec := sealTo(t, []byte("x"), SealOptions{Recipients: [][]byte{k.PublicKey()}})
	pw := sealTo(t, []byte("x"), SealOptions{Passphrases: [][]byte{[]byte("p")}, Argon: testArgon})

	if _, err := openWith(t, rec, nil, []byte("p")); !errors.Is(err, ErrNeedIdentity) {
		t.Fatalf("got %v, want ErrNeedIdentity", err)
	}
	if _, err := openWith(t, pw, k, nil); !errors.Is(err, ErrNeedPassphrase) {
		t.Fatalf("got %v, want ErrNeedPassphrase", err)
	}
}

func TestNotSindook(t *testing.T) {
	for _, junk := range [][]byte{nil, []byte("short"), randomBytes(t, 200)} {
		if _, err := openWith(t, junk, nil, []byte("p")); !errors.Is(err, ErrNotSindook) {
			t.Fatalf("got %v, want ErrNotSindook", err)
		}
	}
}

// TestTamper flips one byte in every region of a single-passphrase v2 file
// (nonce, slot count, slot type, KDF params, salt, wrapped key, header MAC,
// payload) and requires each variant to fail. Offsets follow docs/FORMAT.md.
func TestTamper(t *testing.T) {
	pass := []byte("p")
	blob := sealTo(t, randomBytes(t, 300), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})

	for _, pos := range []int{8, 24, 25, 30, 60, 90, v2PassHeader - 5, v2PassHeader + 5, len(blob) - 1} {
		tampered := append([]byte(nil), blob...)
		tampered[pos] ^= 0x01
		if _, err := openWith(t, tampered, nil, pass); err == nil {
			t.Fatalf("tampering byte %d went undetected", pos)
		}
	}

	macFlip := append([]byte(nil), blob...)
	macFlip[v2PassHeader-macSize+3] ^= 0x01
	if _, err := openWith(t, macFlip, nil, pass); !errors.Is(err, ErrHeaderTampered) {
		t.Fatalf("MAC flip: got %v, want ErrHeaderTampered", err)
	}
}

func TestTruncation(t *testing.T) {
	pass := []byte("p")
	blob := sealTo(t, randomBytes(t, 2*chunkSize+513), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})
	const payloadStart = v2PassHeader
	overhead := chacha20poly1305.Overhead

	cuts := []int{
		payloadStart,                              // payload removed entirely
		payloadStart + chunkSize + overhead,       // cut at first chunk boundary
		payloadStart + 2*(chunkSize+overhead) - 7, // cut inside second chunk
		len(blob) - 1,                             // final tag shortened
	}
	for _, cut := range cuts {
		if _, err := openWith(t, blob[:cut], nil, pass); !errors.Is(err, ErrPayloadCorrupted) {
			t.Fatalf("cut at %d: got %v, want ErrPayloadCorrupted", cut, err)
		}
	}
	extended := append(append([]byte(nil), blob...), 0x00)
	if _, err := openWith(t, extended, nil, pass); !errors.Is(err, ErrPayloadCorrupted) {
		t.Fatalf("extension: got %v, want ErrPayloadCorrupted", err)
	}
}

func TestArgonParamCaps(t *testing.T) {
	bad := []Argon2idParams{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: 65, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: 4, Threads: 1},
		{Time: 1, MemoryKiB: 2 * 1024 * 1024, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: 0},
	}
	for i, p := range bad {
		var sealed bytes.Buffer
		if err := SealPassphrase(&sealed, bytes.NewReader(nil), []byte("p"), p); err == nil {
			t.Fatalf("case %d: invalid params accepted", i)
		}
	}
}

func TestSlotLimits(t *testing.T) {
	k := newIdentity(t)
	tooMany := make([][]byte, maxSlots+1)
	for i := range tooMany {
		tooMany[i] = k.PublicKey()
	}
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(nil), SealOptions{Recipients: tooMany}); err == nil {
		t.Fatal("slot cap not enforced")
	}
	if err := Seal(&sealed, bytes.NewReader(nil), SealOptions{}); err == nil {
		t.Fatal("empty options accepted")
	}
	if err := Seal(io.Discard, bytes.NewReader(nil), SealOptions{
		Passphrases: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
		Argon:       testArgon,
	}); err == nil {
		t.Fatal("passphrase slot cap not enforced")
	}
}
