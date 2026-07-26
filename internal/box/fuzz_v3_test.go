package box

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// The v3 targets attack the three new parsers: the superblock, the header
// slot, and the generation selection that decides which of two slots is
// authoritative. The invariants are the same as for the earlier formats, plus
// one specific to v3: no mutation of a valid arena may promote a superseded
// policy back into the active position.

func v3Seed(f *testing.F) []byte {
	f.Helper()
	id := fuzzIdentity(f)
	var out bytes.Buffer
	if err := SealV3(&out, bytes.NewReader([]byte("fuzz seed payload")),
		SealOptions{Recipients: [][]byte{id.PublicKey()}},
		ArenaOptions{SlotCapacity: minSlotCapacity, ReserveRecipients: -1}); err != nil {
		f.Fatal(err)
	}
	return out.Bytes()
}

func FuzzOpenV3(f *testing.F) {
	id := fuzzIdentity(f)
	seed := v3Seed(f)
	f.Add(seed)
	f.Add([]byte(magicV3))
	f.Add(seed[:superblockSize])

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(data), id, nil); err != nil {
			return
		}
		reopen(t, data, out.Bytes(), id, nil)
	})
}

// FuzzInspectV3 exercises the credential-free path, which is the one an
// attacker reaches first and the one that must never panic or allocate on a
// hostile length field.
func FuzzInspectV3(f *testing.F) {
	seed := v3Seed(f)
	f.Add(seed)
	f.Add(seed[:superblockSize+64])

	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := InspectAt(bytes.NewReader(data))
		if err != nil {
			return
		}
		if info.Version != 3 || info.Arena == nil {
			t.Fatalf("InspectAt accepted a non-v3 file as version %d", info.Version)
		}
		if info.Arena.Active >= 0 && !info.Arena.Headers[info.Arena.Active].Present {
			t.Fatal("selected a header slot that did not parse")
		}
		// The selected generation must be the highest present one.
		for _, h := range info.Arena.Headers {
			if h.Present && h.Generation > info.Arena.Generation {
				t.Fatalf("selected generation %d below a present generation %d", info.Arena.Generation, h.Generation)
			}
		}
	})
}

// FuzzArenaMutation is the security property in fuzz form: an identity that a
// rotation removed must never regain access, whatever bytes of the arena are
// mutated. A mutation may damage the file, may leave the new policy in place,
// or may restore the old slot as a whole, but the old identity must never
// open the file through a normal open.
func FuzzArenaMutation(f *testing.F) {
	removed := fuzzIdentity(f)
	kept, err := xwing.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	plain := []byte("rotated archive payload")

	var sealed bytes.Buffer
	if err := SealV3(&sealed, bytes.NewReader(plain),
		SealOptions{Recipients: [][]byte{removed.PublicKey()}},
		ArenaOptions{SlotCapacity: minSlotCapacity, ReserveRecipients: -1}); err != nil {
		f.Fatal(err)
	}
	rotated := new(bytes.Buffer)
	if err := Rewrap(rotated, bytes.NewReader(sealed.Bytes()), removed, nil,
		SealOptions{Recipients: [][]byte{kept.PublicKey()}}, false); err != nil {
		f.Fatal(err)
	}
	blob := rotated.Bytes()

	f.Add(uint32(0), byte(0x01))
	f.Add(uint32(arenaOffset+8), byte(0xff))
	f.Add(uint32(arenaOffset+minSlotCapacity+8), byte(0xff))

	f.Fuzz(func(t *testing.T, pos uint32, xor byte) {
		if xor == 0 || int(pos) >= len(blob) {
			t.Skip("no-op mutation")
		}
		mutated := append([]byte(nil), blob...)
		mutated[pos] ^= xor
		if err := Open(io.Discard, bytes.NewReader(mutated), removed, nil); err == nil {
			t.Fatalf("mutation at %d restored access for a removed identity", pos)
		}
	})
}

// FuzzRewrapAtArena drives the in-place rotation against hostile arenas. It
// must never panic and never report success on a file it could not parse.
func FuzzRewrapAtArena(f *testing.F) {
	id := fuzzIdentity(f)
	seed := v3Seed(f)
	f.Add(seed)

	next, err := xwing.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	opts := RewrapAtOptions{Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}}}

	f.Fuzz(func(t *testing.T, data []byte) {
		buf := &memFile{data: append([]byte(nil), data...)}
		res, err := RewrapAt(context.Background(), buf, id, nil, opts)
		if err != nil {
			return
		}
		// The assertions are about the header only. A rotation deliberately
		// never reads the payload, so a fuzzer that corrupted payload bytes
		// still gets a successful rotation and a file that fails payload
		// authentication afterwards. That is correct, not a defect.
		newErr := Open(io.Discard, bytes.NewReader(buf.data), next, nil)
		if newErr != nil && !errors.Is(newErr, ErrPayloadCorrupted) {
			t.Fatalf("rotation reported success at generation %d but the new identity cannot reach the payload: %v", res.Generation, newErr)
		}
		// The security property: the replaced identity must be stopped at
		// the header. Reaching payload authentication would mean it
		// recovered the file key.
		oldErr := Open(io.Discard, bytes.NewReader(buf.data), id, nil)
		if oldErr == nil || errors.Is(oldErr, ErrPayloadCorrupted) {
			t.Fatalf("the replaced identity recovered the file key after rotation: %v", oldErr)
		}
	})
}

// memFile is a ReadWriteAtSyncer over a byte slice, so fuzzing a rotation
// needs no filesystem. Writes past the end are refused rather than growing
// the file: a rotation must never extend an archive.
type memFile struct{ data []byte }

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(m.data)) {
		return 0, io.ErrShortWrite
	}
	return copy(m.data[off:], p), nil
}

func (m *memFile) Sync() error { return nil }
