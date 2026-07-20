package box

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// The fuzz targets attack the two hand-written binary parsers (unlockV2,
// unlockV1) and the chunked payload state machine with hostile bytes. The
// invariants are absolute: no panic, no unbounded work, successful opens are
// deterministic, and no modified byte of a valid file ever opens cleanly.
// Crash regressions land in testdata/fuzz and replay under plain go test.

// fuzzIdentity is the fixed identity of the v1 golden fixtures, so fixture
// seeds reach past credential checks into MAC and payload verification.
func fuzzIdentity(tb testing.TB) *xwing.PrivateKey {
	tb.Helper()
	seed, err := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	if err != nil {
		tb.Fatal(err)
	}
	id, err := xwing.NewPrivateKey(seed)
	if err != nil {
		tb.Fatal(err)
	}
	return id
}

func addFixtureSeeds(f *testing.F) {
	for _, name := range []string{"testdata/v1-recipient.sindook", "testdata/v1-passphrase.sindook"} {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
}

// reopen requires that a blob which opened once opens again with identical
// output, catching any state leaking between parses.
func reopen(t *testing.T, data, want []byte, id *xwing.PrivateKey, pass []byte) {
	t.Helper()
	var again bytes.Buffer
	if err := Open(&again, bytes.NewReader(data), id, pass); err != nil {
		t.Fatalf("second open of accepted input failed: %v", err)
	}
	if !bytes.Equal(again.Bytes(), want) {
		t.Fatal("open is not deterministic")
	}
}

func FuzzOpen(f *testing.F) {
	id := fuzzIdentity(f)
	addFixtureSeeds(f)
	var v2 bytes.Buffer
	if err := Seal(&v2, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Recipients: [][]byte{id.PublicKey()}}); err != nil {
		f.Fatal(err)
	}
	f.Add(v2.Bytes())
	f.Add([]byte(magicV1))
	f.Add([]byte(magicV2))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(data), id, nil); err != nil {
			return
		}
		reopen(t, data, out.Bytes(), id, nil)
	})
}

// maxFuzzArgonWork caps declared Time*MemoryKiB per passphrase slot. The
// parser's own ceiling (maxArgonTime, maxArgonMemoryKiB) is deliberately
// generous so files sealed with strong parameters stay openable, but a
// hostile header near that ceiling costs seconds of KDF work before
// rejection, which would stall the fuzzer. Default parameters fit under
// this budget, so both golden fixtures still fuzz the full path.
const maxFuzzArgonWork = 4 * 64 * 1024

// argonWorkBounded reads just enough of a candidate header to find declared
// Argon2id parameters. Truncated or malformed inputs return true: the real
// parser rejects those before any KDF runs.
func argonWorkBounded(data []byte) bool {
	if len(data) < len(magicV2)+1 {
		return true
	}
	switch string(data[:len(magicV2)]) {
	case magicV1:
		if data[8] != modeV1Passphrase || len(data) < 17 {
			return true
		}
		work := uint64(binary.BigEndian.Uint32(data[9:13])) * uint64(binary.BigEndian.Uint32(data[13:17]))
		return work <= maxFuzzArgonWork
	case magicV2:
		if len(data) < 25 {
			return true
		}
		count := int(data[24])
		if count > maxSlots {
			return true
		}
		off := 25
		for i := 0; i < count; i++ {
			if off+3 > len(data) {
				return true
			}
			bodyLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
			body := data[off+3:]
			if bodyLen > len(body) {
				return true
			}
			if data[off] == SlotPassphrase && bodyLen >= 8 {
				work := uint64(binary.BigEndian.Uint32(body[0:4])) * uint64(binary.BigEndian.Uint32(body[4:8]))
				if work > maxFuzzArgonWork {
					return false
				}
			}
			off += 3 + bodyLen
		}
	}
	return true
}

func FuzzOpenPassphrase(f *testing.F) {
	pass := []byte("golden")
	addFixtureSeeds(f)
	var v2 bytes.Buffer
	if err := Seal(&v2, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon}); err != nil {
		f.Fatal(err)
	}
	f.Add(v2.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		if !argonWorkBounded(data) {
			t.Skip("declared KDF work above fuzz budget")
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(data), nil, pass); err != nil {
			return
		}
		reopen(t, data, out.Bytes(), nil, pass)
	})
}

func FuzzSealOpenRoundTrip(f *testing.F) {
	id := fuzzIdentity(f)
	pass := []byte("fuzz")
	f.Add([]byte(nil), false)
	f.Add(bytes.Repeat([]byte{0xA5}, chunkSize+1), true)

	f.Fuzz(func(t *testing.T, plain []byte, usePass bool) {
		opts := SealOptions{Recipients: [][]byte{id.PublicKey()}}
		openID, openPass := id, []byte(nil)
		if usePass {
			opts = SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon}
			openID, openPass = nil, pass
		}
		var sealed bytes.Buffer
		if err := Seal(&sealed, bytes.NewReader(plain), opts); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(sealed.Bytes()), openID, openPass); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatal("round trip mismatch")
		}
	})
}

// FuzzBitFlip generalizes TestTamper from nine chosen offsets to every
// position and value the fuzzer reaches: XORing any byte of a valid sealed
// file must never open cleanly, and appending trailing bytes must fail.
func FuzzBitFlip(f *testing.F) {
	id := fuzzIdentity(f)
	plain := []byte("bit flip corpus payload, long enough to cross into the payload region")
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(plain), SealOptions{Recipients: [][]byte{id.PublicKey()}}); err != nil {
		f.Fatal(err)
	}
	blob := sealed.Bytes()
	f.Add(uint32(8), byte(0x01))
	f.Add(uint32(len(blob)-1), byte(0x80))

	f.Fuzz(func(t *testing.T, pos uint32, xor byte) {
		if xor == 0 {
			t.Skip("identity mutation")
		}
		mutated := append([]byte(nil), blob...)
		if int(pos) >= len(mutated) {
			mutated = append(mutated, xor)
		} else {
			mutated[pos] ^= xor
		}
		if err := Open(io.Discard, bytes.NewReader(mutated), id, nil); err == nil {
			t.Fatalf("mutation pos=%d xor=%#02x opened cleanly", pos, xor)
		}
	})
}
