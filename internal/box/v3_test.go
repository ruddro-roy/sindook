package box

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// --- helpers ---------------------------------------------------------------

// The v1 golden fixtures, restated here so the migration gates read on their
// own. TestV1Fixtures pins the same values from the reading side.
const (
	fixtureSeed       = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	fixturePlaintext  = "sindook v1 golden fixture\n"
	fixturePassphrase = "golden"
)

func fixtureIdentity(t *testing.T) *xwing.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(fixtureSeed)
	if err != nil {
		t.Fatal(err)
	}
	k, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealV3To(t *testing.T, plain []byte, opts SealOptions, a ArenaOptions) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := SealV3(&out, bytes.NewReader(plain), opts, a); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// tempSealed writes a v3 file to disk and returns its path.
func tempSealed(t *testing.T, plain []byte, opts SealOptions, a ArenaOptions) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.sindook")
	if err := os.WriteFile(path, sealV3To(t, plain, opts, a), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func openFileAt(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return f, info.Size()
}

func mustOpenAt(t *testing.T, path string, id *xwing.PrivateKey, pass []byte) []byte {
	t.Helper()
	f, size := openFileAt(t, path)
	var out bytes.Buffer
	if err := OpenAt(context.Background(), f, size, &out, id, pass, false); err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	return out.Bytes()
}

// --- round trips -----------------------------------------------------------

func TestV3RoundTrip(t *testing.T) {
	id := newIdentity(t)
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		blob := sealV3To(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
		got, err := openWith(t, blob, id, nil)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

func TestV3MixedSlotsAndOpenAt(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	pass := []byte("correct horse battery staple")
	plain := randomBytes(t, 200_000)
	opts := SealOptions{
		Recipients:  [][]byte{a.PublicKey(), b.PublicKey()},
		Passphrases: [][]byte{pass},
		Argon:       testArgon,
	}
	path := tempSealed(t, plain, opts, ArenaOptions{})

	for name, cred := range map[string]struct {
		id   *xwing.PrivateKey
		pass []byte
	}{"first": {a, nil}, "second": {b, nil}, "passphrase": {nil, pass}} {
		if got := mustOpenAt(t, path, cred.id, cred.pass); !bytes.Equal(got, plain) {
			t.Fatalf("%s: round trip mismatch", name)
		}
	}
}

func TestV3ArenaGeometry(t *testing.T) {
	id := newIdentity(t)
	blob := sealV3To(t, []byte("x"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	info, err := Inspect(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 3 || info.Arena == nil {
		t.Fatalf("expected a v3 arena, got version %d", info.Version)
	}
	if info.Arena.Generation != 1 || info.Arena.Active != 0 {
		t.Fatalf("fresh file should be generation 1 in slot 0, got generation %d slot %d",
			info.Arena.Generation, info.Arena.Active)
	}
	if !info.Arena.Scrubbed {
		t.Fatal("a freshly sealed arena must be scrubbed")
	}
	want := int64(superblockSize) + 2*int64(info.Arena.SlotCapacity)
	if info.Arena.PayloadOffset != want {
		t.Fatalf("payload offset %d, want %d", info.Arena.PayloadOffset, want)
	}
	// Both slots must hold identical policy at identical generation.
	if len(info.Arena.Headers) != 2 || !info.Arena.Headers[0].Present || !info.Arena.Headers[1].Present {
		t.Fatal("both header slots must be present in a fresh file")
	}
	if info.Arena.Headers[0].Generation != info.Arena.Headers[1].Generation {
		t.Fatal("both header slots of a fresh file must share a generation")
	}
}

// --- the bounded-I/O gate --------------------------------------------------

// TestRewrapAtBoundedIO is the claim this format exists to make true: the
// bytes a rotation touches do not depend on the size of the file.
func TestRewrapAtBoundedIO(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	sizes := []struct {
		name  string
		bytes int64
		spars bool
	}{
		{"1MiB", 1 << 20, false},
		{"1GiB", 1 << 30, true},
		{"100GiB", 100 << 30, true},
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			if tc.spars {
				if testing.Short() {
					t.Skip("large file: skipped under -short")
				}
				if runtime.GOOS == "windows" {
					t.Skip("Truncate does not produce a sparse file on NTFS by default")
				}
			}
			path := tempSealed(t, randomBytes(t, 4096), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
			f, _ := openFileAt(t, path)

			// Extend past the real payload. RewrapAt must never read there,
			// which is exactly what makes the extension harmless.
			if err := f.Truncate(tc.bytes); err != nil {
				t.Skipf("cannot size a %d byte file here: %v", tc.bytes, err)
			}
			if tc.spars && !isSparse(t, path, tc.bytes) {
				t.Skipf("filesystem did not allocate %d bytes sparsely", tc.bytes)
			}

			res, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
				Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
			})
			if err != nil {
				t.Fatal(err)
			}

			capacity := int64(res.SlotCapacity)
			maxRead := superblockSize + 2*capacity + 2*capacity // arena, plus the read-back verification
			maxWrite := 2 * capacity
			if res.BytesRead > maxRead {
				t.Errorf("read %d bytes, bound is %d", res.BytesRead, maxRead)
			}
			if res.BytesWritten != maxWrite {
				t.Errorf("wrote %d bytes, expected exactly %d", res.BytesWritten, maxWrite)
			}
			if res.Syncs != 2 {
				t.Errorf("%d syncs, the commit protocol performs exactly 2", res.Syncs)
			}
			if res.Generation != 2 || res.PreviousGeneration != 1 {
				t.Errorf("generation %d from %d, want 2 from 1", res.Generation, res.PreviousGeneration)
			}

			// The file must not have grown, shrunk, or moved its payload.
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != tc.bytes {
				t.Errorf("file size changed to %d, want %d", info.Size(), tc.bytes)
			}
		})
	}
}

// isSparse reports whether the filesystem stored a nominally huge file
// without allocating it, so the large-file gates skip instead of filling a
// disk on a filesystem that cannot do this.
func isSparse(t *testing.T, path string, nominal int64) bool {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	type blocker interface{ Blocks() int64 }
	sys, ok := info.Sys().(blocker)
	if !ok {
		return true // cannot tell; the caller already checked Truncate succeeded
	}
	return sys.Blocks()*512 < nominal/2
}

// TestRewrapAtLeavesPayloadUntouched proves the payload ciphertext is
// identical byte for byte after a rotation, and still decrypts.
func TestRewrapAtLeavesPayloadUntouched(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300_000)
	path := tempSealed(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectAt(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	off := info.Arena.PayloadOffset

	f, _ := openFileAt(t, path)
	if _, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
		Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before[off:], after[off:]) {
		t.Fatal("payload ciphertext changed during a fast rotation")
	}
	if got := mustOpenAt(t, path, next, nil); !bytes.Equal(got, plain) {
		t.Fatal("rotated file does not decrypt to the original plaintext")
	}
	if _, err := openWith(t, after, id, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("removed identity should no longer open the file, got %v", err)
	}
}

// --- the scrub gate --------------------------------------------------------

// TestRewrapAtScrubsSupersededSlots proves that after a completed rotation no
// byte of the superseded header survives anywhere in the arena. That is the
// difference between "the old policy is no longer selected" and "the old
// policy is no longer present".
func TestRewrapAtScrubsSupersededSlots(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	// Seal with several recipients so the first header is long, then rotate
	// to one: the shorter replacement must still erase the whole tail.
	var many [][]byte
	for i := 0; i < 5; i++ {
		many = append(many, newIdentity(t).PublicKey())
	}
	many = append(many, id.PublicKey())
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: many}, ArenaOptions{})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectAt(bytes.NewReader(before))
	if err != nil {
		t.Fatal(err)
	}
	oldArena := append([]byte(nil), before[arenaOffset:info.Arena.PayloadOffset]...)

	f, _ := openFileAt(t, path)
	if _, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
		Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newArena := after[arenaOffset:info.Arena.PayloadOffset]

	// Every superseded wrapped key was 48 bytes of ciphertext preceded by a
	// KEM ciphertext. Searching for any 32-byte window of the old arena's
	// key-slot region is a strict test: no fragment may survive.
	for _, slot := range info.Arena.Headers {
		if !slot.Present {
			continue
		}
		start := slotFixed
		end := slot.UsedBytes - macSize
		region := oldArena[start:end]
		for i := 0; i+32 <= len(region); i += 32 {
			if bytes.Contains(newArena, region[i:i+32]) {
				t.Fatalf("superseded key material survived the rotation at old offset %d", start+i)
			}
		}
	}

	final, err := InspectAt(bytes.NewReader(after))
	if err != nil {
		t.Fatal(err)
	}
	if !final.Arena.Scrubbed {
		t.Fatal("arena reports itself unscrubbed after a completed rotation")
	}
}

// --- crash injection -------------------------------------------------------

// faultyFile fails the nth write or sync, optionally after writing a prefix,
// which is what a torn write looks like to a reader.
type faultyFile struct {
	inner    ReadWriteAtSyncer
	failAt   int
	torn     int // bytes to write before failing, 0 for none
	writes   int
	syncs    int
	failSync bool
}

var errInjected = errors.New("injected failure")

func (f *faultyFile) ReadAt(p []byte, off int64) (int, error) { return f.inner.ReadAt(p, off) }

func (f *faultyFile) WriteAt(p []byte, off int64) (int, error) {
	f.writes++
	if !f.failSync && f.writes == f.failAt {
		if f.torn > 0 {
			n, _ := f.inner.WriteAt(p[:f.torn], off)
			return n, errInjected
		}
		return 0, errInjected
	}
	return f.inner.WriteAt(p, off)
}

func (f *faultyFile) Sync() error {
	f.syncs++
	if f.failSync && f.syncs == f.failAt {
		return errInjected
	}
	return f.inner.Sync()
}

// TestRewrapAtCrashInjection interrupts a rotation at every write and sync
// boundary, including partial writes, and requires that some authorized
// policy still opens the file afterwards.
func TestRewrapAtCrashInjection(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 70_000)

	type fault struct {
		name     string
		failAt   int
		torn     int
		failSync bool
	}
	faults := []fault{
		{name: "first write fails outright", failAt: 1},
		{name: "first write torn at 100 bytes", failAt: 1, torn: 100},
		{name: "first write torn mid-header", failAt: 1, torn: 1200},
		{name: "first write torn past the header", failAt: 1, torn: 3000},
		{name: "first sync fails", failAt: 1, failSync: true},
		{name: "second write fails outright", failAt: 2},
		{name: "second write torn at 100 bytes", failAt: 2, torn: 100},
		{name: "second write torn mid-header", failAt: 2, torn: 1200},
		{name: "second sync fails", failAt: 2, failSync: true},
	}

	for _, fl := range faults {
		t.Run(fl.name, func(t *testing.T) {
			path := tempSealed(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
			f, size := openFileAt(t, path)

			ff := &faultyFile{inner: f, failAt: fl.failAt, torn: fl.torn, failSync: fl.failSync}
			_, err := RewrapAt(context.Background(), ff, id, nil, RewrapAtOptions{
				Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
			})
			if err == nil {
				t.Fatal("expected the injected failure to surface")
			}

			// After any interruption at least one authorized policy must
			// still open the file, and the plaintext must be intact.
			var out bytes.Buffer
			oldErr := OpenAt(context.Background(), f, size, &out, id, nil, false)
			outNew := bytes.Buffer{}
			newErr := OpenAt(context.Background(), f, size, &outNew, next, nil, false)
			switch {
			case oldErr == nil && bytes.Equal(out.Bytes(), plain):
			case newErr == nil && bytes.Equal(outNew.Bytes(), plain):
			default:
				t.Fatalf("no policy opens the file after interruption: old=%v new=%v", oldErr, newErr)
			}

			// Whichever policy survived, the file must be repairable back to
			// a single scrubbed generation.
			cred, credPass := id, []byte(nil)
			if oldErr != nil {
				cred = next
			}
			if _, err := RepairAt(context.Background(), f, cred, credPass); err != nil {
				t.Fatalf("repair after interruption: %v", err)
			}
			info, err := InspectAt(f)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Arena.Scrubbed {
				t.Fatal("repair did not leave a scrubbed arena")
			}
		})
	}
}

// TestInterruptedRotationIsVisible checks the honest reporting the format
// promises: after a crash between the two commits, both policies are present
// and inspect says so without any credential.
func TestInterruptedRotationIsVisible(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	f, size := openFileAt(t, path)

	ff := &faultyFile{inner: f, failAt: 2}
	if _, err := RewrapAt(context.Background(), ff, id, nil, RewrapAtOptions{
		Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
	}); err == nil {
		t.Fatal("expected the injected failure to surface")
	}

	info, err := InspectAt(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Arena.Scrubbed {
		t.Fatal("an interrupted rotation must not report a scrubbed arena")
	}
	if info.Arena.Headers[0].Generation == info.Arena.Headers[1].Generation {
		t.Fatal("expected the two slots to disagree on generation")
	}

	// The new policy is what a normal open selects.
	var out bytes.Buffer
	if err := OpenAt(context.Background(), f, size, &out, next, nil, false); err != nil {
		t.Fatalf("new policy should be active: %v", err)
	}
	// The old identity must not open the file by normal means, even though
	// its slot is still physically present.
	if err := OpenAt(context.Background(), f, size, io.Discard, id, nil, false); err == nil {
		t.Fatal("a normal open must not fall back to a superseded generation")
	}
	// Explicit recovery reaches it, which is the documented escape hatch.
	if err := OpenAt(context.Background(), f, size, io.Discard, id, nil, true); err != nil {
		t.Fatalf("explicit recovery should reach the superseded generation: %v", err)
	}
}

// --- concurrency -----------------------------------------------------------

func TestRewrapAtStaleGeneration(t *testing.T) {
	id, a, b := newIdentity(t), newIdentity(t), newIdentity(t)
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	f, _ := openFileAt(t, path)

	// Both writers planned against generation 1. The first lands.
	if _, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
		Seal:             SealOptions{Recipients: [][]byte{a.PublicKey(), id.PublicKey()}},
		ExpectGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// The second must be rejected rather than silently discarding the first.
	_, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
		Seal:             SealOptions{Recipients: [][]byte{b.PublicKey(), id.PublicKey()}},
		ExpectGeneration: 1,
	})
	if !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected ErrStaleGeneration, got %v", err)
	}
	if _, err := openWith(t, readFile(t, path), a, nil); err != nil {
		t.Fatalf("the winning rotation should still be in force: %v", err)
	}
}

func TestRewrapFileTakesExclusiveLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("lock semantics differ; covered by the unix path")
	}
	id, next := newIdentity(t), newIdentity(t)
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	// A rotation running inside another rotation's lock must fail fast.
	err := withLockedFile(path, func(*os.File) error {
		_, inner := RewrapFile(context.Background(), path, id, nil, RewrapAtOptions{
			Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
		})
		if inner == nil {
			return errors.New("second writer took a lock that was already held")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// With the lock released the same rotation succeeds.
	if _, err := RewrapFile(context.Background(), path, id, nil, RewrapAtOptions{
		Seal: SealOptions{Recipients: [][]byte{next.PublicKey()}},
	}); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- corruption ------------------------------------------------------------

// TestSuperblockCorruption flips each superblock field and requires a clean
// rejection rather than a misparse.
func TestSuperblockCorruption(t *testing.T) {
	id := newIdentity(t)
	base := sealV3To(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"magic", func(b []byte) { b[0] ^= 0xff }},
		{"version", func(b []byte) { binary.BigEndian.PutUint16(b[8:10], 4) }},
		{"superblock length", func(b []byte) { binary.BigEndian.PutUint16(b[10:12], 128) }},
		{"critical feature flag", func(b []byte) { binary.BigEndian.PutUint32(b[12:16], 1) }},
		{"file identifier", func(b []byte) { b[16] ^= 0xff }},
		{"arena offset", func(b []byte) { binary.BigEndian.PutUint32(b[32:36], 128) }},
		{"slot capacity", func(b []byte) { binary.BigEndian.PutUint32(b[36:40], 5000) }},
		{"payload offset", func(b []byte) { binary.BigEndian.PutUint64(b[40:48], 999) }},
		{"crc", func(b []byte) { b[48] ^= 0xff }},
		{"reserved", func(b []byte) { b[52] ^= 0xff }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := append([]byte(nil), base...)
			tc.mutate(blob)
			if _, err := openWith(t, blob, id, nil); err == nil {
				t.Fatal("corrupted superblock opened successfully")
			}
			if _, err := InspectAt(bytes.NewReader(blob)); err == nil {
				t.Fatal("corrupted superblock inspected successfully")
			}
		})
	}
}

// TestHeaderSlotCorruption damages one slot at a time and requires the other
// to carry the file, then damages both and requires a clear failure.
func TestHeaderSlotCorruption(t *testing.T) {
	id := newIdentity(t)
	plain := []byte("payload that must survive one damaged slot")
	base := sealV3To(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	info, err := InspectAt(bytes.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	capacity := int(info.Arena.SlotCapacity)

	fields := []struct {
		name string
		at   int
	}{
		{"slot magic", 0},
		{"slot version", 4},
		{"slot index", 6},
		{"content algorithm", 7},
		{"generation", 15},
		{"used length", 19},
		{"capacity", 23},
		{"crc", 27},
		{"critical flags", 31},
		{"content nonce", 40},
		{"policy digest", 60},
		{"key slot count", 81},
		{"key slot body", slotFixed + 40},
		{"mac", slotMinUsed + 1000},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			for _, slot := range []int{0, 1} {
				blob := append([]byte(nil), base...)
				blob[arenaOffset+slot*capacity+f.at] ^= 0xff
				got, err := openWith(t, blob, id, nil)
				if err != nil {
					t.Fatalf("slot %d damaged at %s: the intact slot should have carried the file, got %v", slot, f.name, err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("slot %d damaged at %s: wrong plaintext", slot, f.name)
				}
			}
			// Both slots damaged: no silent success.
			blob := append([]byte(nil), base...)
			blob[arenaOffset+f.at] ^= 0xff
			blob[arenaOffset+capacity+f.at] ^= 0xff
			if _, err := openWith(t, blob, id, nil); err == nil {
				t.Fatalf("both slots damaged at %s but the file opened", f.name)
			}
		})
	}
}

// TestSlotTransplantRejected copies slot 0 verbatim over slot 1. The index
// check catches it before any key material is considered.
func TestSlotTransplantRejected(t *testing.T) {
	id := newIdentity(t)
	base := sealV3To(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	info, err := InspectAt(bytes.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	capacity := int(info.Arena.SlotCapacity)

	blob := append([]byte(nil), base...)
	copy(blob[arenaOffset+capacity:arenaOffset+2*capacity], blob[arenaOffset:arenaOffset+capacity])

	got, err := InspectAt(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if got.Arena.Headers[1].Present {
		t.Fatal("a slot carrying the wrong index must not parse")
	}
	if _, err := openWith(t, blob, id, nil); err != nil {
		t.Fatalf("slot 0 should still carry the file: %v", err)
	}
}

// TestSuperblockSwapDetected replaces the superblock with one from another
// file. The geometry parses, so only the slot MAC catches it.
func TestSuperblockSwapDetected(t *testing.T) {
	id := newIdentity(t)
	opts := SealOptions{Recipients: [][]byte{id.PublicKey()}}
	victim := sealV3To(t, []byte("payload"), opts, ArenaOptions{})
	other := sealV3To(t, []byte("payload"), opts, ArenaOptions{})

	blob := append([]byte(nil), victim...)
	copy(blob[:superblockSize], other[:superblockSize])
	// The swapped file identifier is associated data for every key slot, so
	// unwrapping fails before the MAC is even reached. Either rejection is
	// correct; silently opening is not.
	_, err := openWith(t, blob, id, nil)
	if !errors.Is(err, ErrWrongKey) && !errors.Is(err, ErrHeaderTampered) {
		t.Fatalf("expected a swapped superblock to be rejected, got %v", err)
	}
}

// --- capacity --------------------------------------------------------------

func TestCapacityErrorIsTypedAndActionable(t *testing.T) {
	id := newIdentity(t)
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}},
		ArenaOptions{SlotCapacity: minSlotCapacity, ReserveRecipients: -1})
	f, _ := openFileAt(t, path)

	// minSlotCapacity holds three X-Wing slots; ask for eight.
	var many [][]byte
	for i := 0; i < 8; i++ {
		many = append(many, newIdentity(t).PublicKey())
	}
	_, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{Seal: SealOptions{Recipients: many}})

	var ce *CapacityError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a CapacityError, got %v", err)
	}
	if ce.Required <= ce.Available {
		t.Fatalf("capacity error reports required %d <= available %d", ce.Required, ce.Available)
	}
	// The arena must be untouched: the original policy still opens the file.
	if _, err := openWith(t, readFile(t, path), id, nil); err != nil {
		t.Fatalf("a failed capacity check must leave the file unchanged: %v", err)
	}
}

func TestDefaultCapacityAbsorbsGrowth(t *testing.T) {
	id := newIdentity(t)
	path := tempSealed(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	f, _ := openFileAt(t, path)

	// The documented default reserves room for four more recipients.
	recipients := [][]byte{id.PublicKey()}
	for i := 0; i < defaultReserveRecipients; i++ {
		recipients = append(recipients, newIdentity(t).PublicKey())
	}
	if _, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{Seal: SealOptions{Recipients: recipients}}); err != nil {
		t.Fatalf("default arena should absorb %d more recipients: %v", defaultReserveRecipients, err)
	}
}

// --- migration -------------------------------------------------------------

func TestMigrateRoundTripEveryLegacyVersion(t *testing.T) {
	id := newIdentity(t)
	pass := []byte("legacy passphrase")
	plain := randomBytes(t, 150_000)

	v1Recipient, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	v1Passphrase, err := os.ReadFile("testdata/v1-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		blob []byte
		id   *xwing.PrivateKey
		pass []byte
		opts SealOptions
		want []byte
		from int
	}{
		{
			name: "v2 recipient",
			blob: sealTo(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}),
			id:   id,
			opts: SealOptions{Recipients: [][]byte{id.PublicKey()}},
			want: plain,
			from: 2,
		},
		{
			name: "v2 passphrase, slot set inferred",
			blob: sealTo(t, plain, SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon}),
			pass: pass,
			want: plain,
			from: 2,
		},
		{
			name: "v1 recipient fixture",
			blob: v1Recipient,
			id:   fixtureIdentity(t),
			opts: SealOptions{Recipients: [][]byte{fixtureIdentity(t).PublicKey()}},
			want: []byte(fixturePlaintext),
			from: 1,
		},
		{
			name: "v1 passphrase fixture, slot set inferred",
			blob: v1Passphrase,
			pass: []byte(fixturePassphrase),
			want: []byte(fixturePlaintext),
			from: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "legacy.sindook")
			if err := os.WriteFile(path, tc.blob, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}

			res, err := MigrateFile(context.Background(), path, tc.id, tc.pass, tc.opts, ArenaOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if res.FromVersion != tc.from || res.ToVersion != 3 {
				t.Fatalf("migrated %d to %d, want %d to 3", res.FromVersion, res.ToVersion, tc.from)
			}

			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if after.Mode().Perm() != before.Mode().Perm() {
				t.Errorf("permissions changed from %v to %v", before.Mode().Perm(), after.Mode().Perm())
			}
			if !after.ModTime().Equal(before.ModTime()) {
				t.Errorf("modification time changed from %v to %v", before.ModTime(), after.ModTime())
			}

			if got := mustOpenAt(t, path, tc.id, tc.pass); !bytes.Equal(got, tc.want) {
				t.Fatal("migrated file does not decrypt to the original plaintext")
			}
			// A migrated file must support bounded rotation, which is the
			// entire point of migrating.
			next := newIdentity(t)
			seal := SealOptions{Recipients: [][]byte{next.PublicKey()}}
			if tc.pass != nil && tc.id == nil {
				seal = SealOptions{Passphrases: [][]byte{tc.pass}, Argon: testArgon}
			}
			r, err := RewrapFile(context.Background(), path, tc.id, tc.pass, RewrapAtOptions{Seal: seal})
			if err != nil {
				t.Fatalf("rotation after migration: %v", err)
			}
			if r.BytesRead > superblockSize+4*int64(r.SlotCapacity) {
				t.Errorf("rotation after migration read %d bytes, not bounded", r.BytesRead)
			}
		})
	}
}

// TestMigrateGrowsTheArena covers the documented way out of a capacity error:
// an explicit one-time migration to a larger arena.
func TestMigrateGrowsTheArena(t *testing.T) {
	id := newIdentity(t)
	plain := randomBytes(t, 100_000)
	path := tempSealed(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}},
		ArenaOptions{SlotCapacity: minSlotCapacity, ReserveRecipients: -1})

	var many [][]byte
	for i := 0; i < 10; i++ {
		many = append(many, newIdentity(t).PublicKey())
	}
	many = append(many, id.PublicKey())

	// Too many recipients for the arena this file was sealed with.
	var ce *CapacityError
	if _, err := RewrapFile(context.Background(), path, id, nil, RewrapAtOptions{Seal: SealOptions{Recipients: many}}); !errors.As(err, &ce) {
		t.Fatalf("expected a CapacityError, got %v", err)
	}

	// Migrating to a larger arena is the way through, and it is explicit.
	grown := uint32(roundCapacity(ce.Required))
	if _, err := MigrateFile(context.Background(), path, id, nil,
		SealOptions{Recipients: many}, ArenaOptions{SlotCapacity: grown}); err != nil {
		t.Fatal(err)
	}
	info, err := InspectAt(bytes.NewReader(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Arena.SlotCapacity != grown {
		t.Fatalf("arena is %d bytes, want %d", info.Arena.SlotCapacity, grown)
	}
	if got := mustOpenAt(t, path, id, nil); !bytes.Equal(got, plain) {
		t.Fatal("growing the arena changed the plaintext")
	}
	// And the grown file rotates in place again.
	if _, err := RewrapFile(context.Background(), path, id, nil,
		RewrapAtOptions{Seal: SealOptions{Recipients: many}}); err != nil {
		t.Fatalf("rotation after growing the arena: %v", err)
	}
}

func TestMigrateRefusesToGuessRecipients(t *testing.T) {
	id := newIdentity(t)
	path := filepath.Join(t.TempDir(), "legacy.sindook")
	blob := sealTo(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := MigrateFile(context.Background(), path, id, nil, SealOptions{}, ArenaOptions{})
	if !errors.Is(err, ErrRecipientsRequired) {
		t.Fatalf("expected ErrRecipientsRequired, got %v", err)
	}
	if !bytes.Equal(readFile(t, path), blob) {
		t.Fatal("a refused migration must leave the original file untouched")
	}
}

func TestRewrapAtRefusesLegacyFormats(t *testing.T) {
	id := newIdentity(t)
	path := filepath.Join(t.TempDir(), "legacy.sindook")
	if err := os.WriteFile(path, sealTo(t, []byte("payload"), SealOptions{Recipients: [][]byte{id.PublicKey()}}), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := openFileAt(t, path)
	_, err := RewrapAt(context.Background(), f, id, nil, RewrapAtOptions{
		Seal: SealOptions{Recipients: [][]byte{newIdentity(t).PublicKey()}},
	})
	if !errors.Is(err, ErrNotV3) {
		t.Fatalf("expected ErrNotV3 with migration advice, got %v", err)
	}
}

// TestStreamRewrapPreservesV3 checks that rotating through a stream, as
// happens with -o or with ASCII armor, does not downgrade the format.
func TestStreamRewrapPreservesV3(t *testing.T) {
	id, next := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 80_000)
	blob := sealV3To(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	var out bytes.Buffer
	if err := Rewrap(&out, bytes.NewReader(blob), id, nil, SealOptions{Recipients: [][]byte{next.PublicKey()}}, false); err != nil {
		t.Fatal(err)
	}
	info, err := InspectAt(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 3 {
		t.Fatalf("stream rotation produced format v%d", info.Version)
	}
	if info.Arena.Generation != 2 {
		t.Fatalf("stream rotation left generation %d, want 2", info.Arena.Generation)
	}
	if !info.Arena.Scrubbed {
		t.Fatal("stream rotation must produce a scrubbed arena")
	}
	got, err := openWith(t, out.Bytes(), next, nil)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("stream rotation broke the payload: %v", err)
	}
	// Same file identifier: a rotation does not create a new archive.
	orig, err := InspectAt(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if info.Arena.FileID != orig.Arena.FileID {
		t.Fatal("stream rotation changed the file identifier")
	}
}

func TestStreamRewrapDeepV3(t *testing.T) {
	id := newIdentity(t)
	plain := randomBytes(t, 80_000)
	blob := sealV3To(t, plain, SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})

	var out bytes.Buffer
	if err := Rewrap(&out, bytes.NewReader(blob), id, nil, SealOptions{Recipients: [][]byte{id.PublicKey()}}, true); err != nil {
		t.Fatal(err)
	}
	info, err := InspectAt(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 3 {
		t.Fatalf("deep rotation produced format v%d", info.Version)
	}
	got, err := openWith(t, out.Bytes(), id, nil)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("deep rotation broke the payload: %v", err)
	}
	// Deep mode must actually change the ciphertext: that is its purpose.
	offset := info.Arena.PayloadOffset
	if bytes.Equal(blob[offset:], out.Bytes()[offset:]) {
		t.Fatal("deep rotation left the payload ciphertext unchanged")
	}
}

// --- cancellation ----------------------------------------------------------

func TestVerifyAtRespectsCancellation(t *testing.T) {
	id := newIdentity(t)
	path := tempSealed(t, randomBytes(t, 2<<20), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	f, size := openFileAt(t, path)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyAt(ctx, f, size, id, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestVerifyAtDetectsPayloadDamage(t *testing.T) {
	id := newIdentity(t)
	path := tempSealed(t, randomBytes(t, 200_000), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{})
	f, size := openFileAt(t, path)
	if err := VerifyAt(context.Background(), f, size, id, nil); err != nil {
		t.Fatal(err)
	}

	info, err := InspectAt(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xff}, info.Arena.PayloadOffset+100); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAt(context.Background(), f, size, id, nil); !errors.Is(err, ErrPayloadCorrupted) {
		t.Fatalf("expected ErrPayloadCorrupted, got %v", err)
	}
}

// --- benchmark -------------------------------------------------------------

// BenchmarkRewrapAt reports the rotation cost against payload sizes spanning
// four orders of magnitude. The numbers must not move with the payload.
func BenchmarkRewrapAt(b *testing.B) {
	for _, size := range []int64{1 << 20, 1 << 26, 1 << 30} {
		b.Run(fmt.Sprintf("payload=%dMiB", size>>20), func(b *testing.B) {
			id, err := xwing.GenerateKey()
			if err != nil {
				b.Fatal(err)
			}
			path := filepath.Join(b.TempDir(), "archive.sindook")
			var buf bytes.Buffer
			if err := SealV3(&buf, bytes.NewReader([]byte("payload")), SealOptions{Recipients: [][]byte{id.PublicKey()}}, ArenaOptions{}); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				b.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				b.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(size); err != nil {
				b.Skipf("cannot size a %d byte file here: %v", size, err)
			}

			next, err := xwing.GenerateKey()
			if err != nil {
				b.Fatal(err)
			}
			opts := RewrapAtOptions{Seal: SealOptions{Recipients: [][]byte{id.PublicKey(), next.PublicKey()}}}

			b.ResetTimer()
			var res *RewrapResult
			for i := 0; i < b.N; i++ {
				if res, err = RewrapAt(context.Background(), f, id, nil, opts); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(res.BytesRead), "bytes_read/op")
			b.ReportMetric(float64(res.BytesWritten), "bytes_written/op")
			b.ReportMetric(float64(res.Syncs), "syncs/op")
		})
	}
}
