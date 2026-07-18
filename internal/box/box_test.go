package box

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/ruddro-roy/sindook/internal/xwing"
)

// Small parameters keep the Argon2id tests fast; validity is still enforced.
var testArgon = Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func roundTripSizes() []int {
	return []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 2*chunkSize + 513}
}

func TestRecipientRoundTrip(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		var sealed bytes.Buffer
		if err := SealRecipient(&sealed, bytes.NewReader(plain), k.PublicKey()); err != nil {
			t.Fatalf("n=%d: seal: %v", n, err)
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(sealed.Bytes()), k, nil); err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		var sealed bytes.Buffer
		if err := SealPassphrase(&sealed, bytes.NewReader(plain), pass, testArgon); err != nil {
			t.Fatalf("n=%d: seal: %v", n, err)
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(sealed.Bytes()), nil, pass); err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestWrongIdentity(t *testing.T) {
	k1, _ := xwing.GenerateKey()
	k2, _ := xwing.GenerateKey()
	var sealed bytes.Buffer
	if err := SealRecipient(&sealed, bytes.NewReader([]byte("secret")), k1.PublicKey()); err != nil {
		t.Fatal(err)
	}
	err := Open(io.Discard, bytes.NewReader(sealed.Bytes()), k2, nil)
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	var sealed bytes.Buffer
	if err := SealPassphrase(&sealed, bytes.NewReader([]byte("secret")), []byte("right"), testArgon); err != nil {
		t.Fatal(err)
	}
	err := Open(io.Discard, bytes.NewReader(sealed.Bytes()), nil, []byte("wrong"))
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestModeErrors(t *testing.T) {
	k, _ := xwing.GenerateKey()
	var rec, pw bytes.Buffer
	if err := SealRecipient(&rec, bytes.NewReader([]byte("x")), k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := SealPassphrase(&pw, bytes.NewReader([]byte("x")), []byte("p"), testArgon); err != nil {
		t.Fatal(err)
	}
	if err := Open(io.Discard, bytes.NewReader(rec.Bytes()), nil, []byte("p")); !errors.Is(err, ErrNeedIdentity) {
		t.Fatalf("got %v, want ErrNeedIdentity", err)
	}
	if err := Open(io.Discard, bytes.NewReader(pw.Bytes()), k, nil); !errors.Is(err, ErrNeedPassphrase) {
		t.Fatalf("got %v, want ErrNeedPassphrase", err)
	}
}

func TestNotSindook(t *testing.T) {
	for _, junk := range [][]byte{nil, []byte("short"), randomBytes(t, 200)} {
		if err := Open(io.Discard, bytes.NewReader(junk), nil, []byte("p")); !errors.Is(err, ErrNotSindook) {
			t.Fatalf("got %v, want ErrNotSindook", err)
		}
	}
}

// TestTamper flips one byte in every region of a passphrase-mode file
// (header params, salt, wrapped key, payload, final tag) and requires each
// variant to fail. Offsets follow docs/FORMAT.md: 50-byte header, 48-byte
// wrapped key, payload at 98.
func TestTamper(t *testing.T) {
	pass := []byte("p")
	var sealed bytes.Buffer
	if err := SealPassphrase(&sealed, bytes.NewReader(randomBytes(t, 300)), pass, testArgon); err != nil {
		t.Fatal(err)
	}
	blob := sealed.Bytes()
	for _, pos := range []int{8, 9, 20, 40, 60, 98, len(blob) - 1} {
		tampered := append([]byte(nil), blob...)
		tampered[pos] ^= 0x01
		if err := Open(io.Discard, bytes.NewReader(tampered), nil, pass); err == nil {
			t.Fatalf("tampering byte %d went undetected", pos)
		}
	}
}

func TestTruncation(t *testing.T) {
	pass := []byte("p")
	var sealed bytes.Buffer
	if err := SealPassphrase(&sealed, bytes.NewReader(randomBytes(t, 2*chunkSize+513)), pass, testArgon); err != nil {
		t.Fatal(err)
	}
	blob := sealed.Bytes()
	const payloadStart = 98
	cuts := []int{
		payloadStart,                        // payload removed entirely
		payloadStart + chunkSize + 16,       // cut at first chunk boundary
		payloadStart + 2*(chunkSize+16) - 7, // cut inside second chunk
		len(blob) - 1,                       // final tag shortened
	}
	for _, cut := range cuts {
		err := Open(io.Discard, bytes.NewReader(blob[:cut]), nil, pass)
		if !errors.Is(err, ErrPayloadCorrupted) {
			t.Fatalf("cut at %d: got %v, want ErrPayloadCorrupted", cut, err)
		}
	}
	extended := append(append([]byte(nil), blob...), 0x00)
	if err := Open(io.Discard, bytes.NewReader(extended), nil, pass); !errors.Is(err, ErrPayloadCorrupted) {
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
