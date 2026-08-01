package box

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ruddro-roy/sindook/internal/filelock"
	"github.com/ruddro-roy/sindook/xwing"
)

// ReadWriteAtSyncer is what a bounded rotation needs from a file: positioned
// reads, positioned writes, and a durability barrier. *os.File satisfies it.
// Nothing here seeks, so a rotation never depends on or disturbs a file
// offset shared with another reader.
type ReadWriteAtSyncer interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// counter records the I/O a rotation actually performed, so the bounded-I/O
// claim is measured rather than asserted.
type counter struct {
	inner        ReadWriteAtSyncer
	bytesRead    int64
	bytesWritten int64
	syncs        int
}

func (c *counter) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.inner.ReadAt(p, off)
	c.bytesRead += int64(n)
	return n, err
}

func (c *counter) WriteAt(p []byte, off int64) (int, error) {
	n, err := c.inner.WriteAt(p, off)
	c.bytesWritten += int64(n)
	return n, err
}

func (c *counter) Sync() error {
	c.syncs++
	return c.inner.Sync()
}

// RewrapAtOptions describes one bounded rotation.
type RewrapAtOptions struct {
	// Seal is the new slot set. It replaces the old one entirely.
	Seal SealOptions
	// PolicyDigest is the canonical digest of the policy that produced Seal,
	// or nil to clear it.
	PolicyDigest []byte
	// ExpectGeneration, when non-zero, is the generation the caller believes
	// is current. A mismatch fails with ErrStaleGeneration instead of
	// overwriting a rotation that landed in between.
	ExpectGeneration uint64
}

// RewrapResult is the audit record of a completed rotation. Every field is
// derived from public metadata: nothing here is secret.
type RewrapResult struct {
	FileID               string `json:"file_id"`
	PreviousGeneration   uint64 `json:"previous_generation"`
	Generation           uint64 `json:"generation"`
	PreviousPolicyDigest string `json:"previous_policy_digest,omitempty"`
	PolicyDigest         string `json:"policy_digest,omitempty"`
	SlotCapacity         uint32 `json:"slot_capacity"`
	KeySlots             int    `json:"key_slots"`
	BytesRead            int64  `json:"bytes_read"`
	BytesWritten         int64  `json:"bytes_written"`
	Syncs                int    `json:"syncs"`
}

func digestString(d []byte) string {
	if allZero(d) {
		return ""
	}
	return hex.EncodeToString(d)
}

// readArenaAt loads the superblock and both header slots. This is the whole
// read cost of a rotation: 64 bytes plus the arena, whatever the file size.
func readArenaAt(r io.ReaderAt) (*arena, error) {
	sbBuf := make([]byte, superblockSize)
	if _, err := r.ReadAt(sbBuf, 0); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotSindook
		}
		return nil, err
	}
	if s := string(sbBuf[0:8]); s == magicV1 || s == magicV2 {
		return nil, ErrNotV3
	}
	sb, err := parseSuperblock(sbBuf)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, sb.arenaSize())
	if _, err := r.ReadAt(raw, arenaOffset); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNoReadableHeader
		}
		return nil, err
	}
	return parseArena(sb, raw)
}

// commit writes one header into both arena slots with a durability barrier
// and a read-back verification between them. Ordering is the whole point:
// the slot that is not currently authoritative is written first, so an
// interruption before it is durable leaves the previous policy untouched,
// and an interruption after it leaves the new policy already readable.
func commit(c *counter, sb *superblock, slot *headerSlot, fileKey []byte, first int) error {
	second := 1 - first
	for phase, index := range [2]int{first, second} {
		slot.index = byte(index)
		buf, err := slot.encode(sb, fileKey)
		if err != nil {
			return err
		}
		if _, err := c.WriteAt(buf, sb.slotOffset(index)); err != nil {
			return commitError(phase, index, "writing", err)
		}
		if err := c.Sync(); err != nil {
			return commitError(phase, index, "syncing", err)
		}
		if phase != 0 {
			continue
		}
		// Read the new header back before the old one is destroyed. A
		// storage stack that silently dropped the write is caught here,
		// while the previous policy is still intact and recoverable.
		if err := verifySlotAt(c, sb, index, slot.generation, fileKey); err != nil {
			return fmt.Errorf("sindook: header slot %d did not survive the write, the previous policy is unchanged: %w", index, err)
		}
	}
	return nil
}

// commitError says which side of the commit point a failure landed on. That
// distinction is the difference between "nothing happened" and "the new
// policy is live but the old one has not been erased yet", and a caller that
// only sees "write failed" would draw the wrong conclusion about a file whose
// access has, in fact, already changed.
func commitError(phase, index int, verb string, err error) error {
	if phase == 0 {
		return fmt.Errorf("sindook: %s header slot %d, the previous policy is unchanged: %w", verb, index, err)
	}
	return fmt.Errorf("sindook: %s header slot %d: the new policy is in force but the superseded one was not erased, run sindook repair: %w", verb, index, err)
}

func verifySlotAt(r io.ReaderAt, sb *superblock, index int, wantGen uint64, fileKey []byte) error {
	buf := make([]byte, sb.slotCapacity)
	if _, err := r.ReadAt(buf, sb.slotOffset(index)); err != nil {
		return err
	}
	slot, err := parseSlot(sb, index, buf)
	if err != nil {
		return err
	}
	if slot.generation != wantGen {
		return ErrStaleGeneration
	}
	return slot.verifyMAC(sb, fileKey, buf)
}

// RewrapAt replaces the key slots of a v3 file in place. It reads and writes
// only the header arena: payload ciphertext is never read, never decrypted,
// and never re-encrypted, so the cost is the same for a one byte file and a
// hundred gigabyte one.
//
// The caller is responsible for holding an exclusive lock on the file;
// RewrapFile does that. ExpectGeneration covers what a lock cannot, namely a
// caller that planned against a header some other writer has since replaced.
func RewrapAt(ctx context.Context, f ReadWriteAtSyncer, identity *xwing.PrivateKey, passphrase []byte, o RewrapAtOptions) (*RewrapResult, error) {
	if err := o.Seal.validate(); err != nil {
		return nil, err
	}
	if len(o.PolicyDigest) != 0 && len(o.PolicyDigest) != policyDigestSize {
		return nil, fmt.Errorf("sindook: policy digest must be %d bytes, got %d", policyDigestSize, len(o.PolicyDigest))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c := &counter{inner: f}
	a, err := readArenaAt(c)
	if err != nil {
		return nil, err
	}
	u, err := unlockArena(a, identity, passphrase, openOptions{})
	if err != nil {
		return nil, err
	}
	if o.ExpectGeneration != 0 && o.ExpectGeneration != u.slot.generation {
		return nil, fmt.Errorf("%w: expected generation %d, found %d", ErrStaleGeneration, o.ExpectGeneration, u.slot.generation)
	}

	// Number the new header above every generation present, not just the
	// active one, so an interrupted predecessor's generation is never reused.
	next := &headerSlot{
		contentAlg:   u.slot.contentAlg,
		generation:   a.highestGeneration() + 1,
		contentNonce: u.slot.contentNonce,
	}
	copy(next.policyDigest[:], o.PolicyDigest)
	if next.keySlots, err = buildKeySlots(u.fileKey, profileV3(a.sb.fileID[:]), o.Seal); err != nil {
		return nil, err
	}
	// Size the header before touching the file so a policy that cannot fit
	// fails with the arena intact.
	if _, err := next.encode(a.sb, u.fileKey); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := commit(c, a.sb, next, u.fileKey, 1-u.index); err != nil {
		return nil, err
	}
	return &RewrapResult{
		FileID:               hex.EncodeToString(a.sb.fileID[:]),
		PreviousGeneration:   u.slot.generation,
		Generation:           next.generation,
		PreviousPolicyDigest: digestString(u.slot.policyDigest[:]),
		PolicyDigest:         digestString(next.policyDigest[:]),
		SlotCapacity:         a.sb.slotCapacity,
		KeySlots:             len(next.keySlots),
		BytesRead:            c.bytesRead,
		BytesWritten:         c.bytesWritten,
		Syncs:                c.syncs,
	}, nil
}

// RepairAt completes the scrub an interrupted rotation left unfinished. It
// writes the authoritative header into both slots without changing the
// policy or the generation, after which no superseded wrapped key material
// remains anywhere in the arena.
func RepairAt(ctx context.Context, f ReadWriteAtSyncer, identity *xwing.PrivateKey, passphrase []byte) (*RewrapResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &counter{inner: f}
	a, err := readArenaAt(c)
	if err != nil {
		return nil, err
	}
	u, err := unlockArena(a, identity, passphrase, openOptions{})
	if err != nil {
		return nil, err
	}
	if a.scrubbed() {
		return &RewrapResult{
			FileID:             hex.EncodeToString(a.sb.fileID[:]),
			PreviousGeneration: u.slot.generation,
			Generation:         u.slot.generation,
			PolicyDigest:       digestString(u.slot.policyDigest[:]),
			SlotCapacity:       a.sb.slotCapacity,
			KeySlots:           len(u.slot.keySlots),
			BytesRead:          c.bytesRead,
			BytesWritten:       c.bytesWritten,
			Syncs:              c.syncs,
		}, nil
	}
	// Write the stale slot first: the authoritative one must stay readable
	// until its replacement is durable and verified.
	if err := commit(c, a.sb, u.slot, u.fileKey, 1-u.index); err != nil {
		return nil, err
	}
	return &RewrapResult{
		FileID:             hex.EncodeToString(a.sb.fileID[:]),
		PreviousGeneration: u.slot.generation,
		Generation:         u.slot.generation,
		PolicyDigest:       digestString(u.slot.policyDigest[:]),
		SlotCapacity:       a.sb.slotCapacity,
		KeySlots:           len(u.slot.keySlots),
		BytesRead:          c.bytesRead,
		BytesWritten:       c.bytesWritten,
		Syncs:              c.syncs,
	}, nil
}

// withLockedFile opens path read-write, takes an exclusive advisory lock, and
// runs fn. Rotation refuses to run unlocked: a concurrent header write is the
// one failure this format cannot recover from cleanly.
func withLockedFile(path string, fn func(*os.File) error) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	lock, err := filelock.TryLock(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer lock.Release()
	if err := fn(f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// RewrapFile is RewrapAt with the exclusive lock the protocol assumes.
func RewrapFile(ctx context.Context, path string, identity *xwing.PrivateKey, passphrase []byte, o RewrapAtOptions) (*RewrapResult, error) {
	var res *RewrapResult
	err := withLockedFile(path, func(f *os.File) error {
		var err error
		res, err = RewrapAt(ctx, f, identity, passphrase, o)
		return err
	})
	return res, err
}

// RepairFile is RepairAt with the exclusive lock the protocol assumes.
func RepairFile(ctx context.Context, path string, identity *xwing.PrivateKey, passphrase []byte) (*RewrapResult, error) {
	var res *RewrapResult
	err := withLockedFile(path, func(f *os.File) error {
		var err error
		res, err = RepairAt(ctx, f, identity, passphrase)
		return err
	})
	return res, err
}

// OpenAt decrypts a v3 file into dst reading only the arena and the payload,
// with no rewind and no temporary copy.
func OpenAt(ctx context.Context, r io.ReaderAt, size int64, dst io.Writer, identity *xwing.PrivateKey, passphrase []byte, allowSuperseded bool) error {
	a, err := readArenaAt(r)
	if err != nil {
		return err
	}
	u, err := unlockArena(a, identity, passphrase, openOptions{allowSuperseded: allowSuperseded})
	if err != nil {
		return err
	}
	key, err := u.payloadKey()
	if err != nil {
		return err
	}
	off := a.sb.payloadOffset()
	if size < off {
		return ErrPayloadCorrupted
	}
	return openPayloadFrom(ctx, io.NewSectionReader(r, off, size-off), dst, key)
}

// VerifyAt authenticates a v3 file end to end without writing plaintext
// anywhere. It is the drill an adopter runs to prove a retained archive still
// opens.
func VerifyAt(ctx context.Context, r io.ReaderAt, size int64, identity *xwing.PrivateKey, passphrase []byte) error {
	return OpenAt(ctx, r, size, io.Discard, identity, passphrase, false)
}
