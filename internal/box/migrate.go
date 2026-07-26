package box

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

// ErrRecipientsRequired explains the one thing migration cannot infer. A
// sealed file stores KEM ciphertexts, not recipient public keys, so nothing
// in a v1 or v2 file says who its recipients were. Re-wrapping into a v3
// arena needs the caller to say who should still have access.
var ErrRecipientsRequired = errors.New("sindook: migrating a file with recipient slots needs the new recipient list (-r or -R): a sealed file does not record who its recipients are")

// MigrateResult reports what a one-time conversion produced.
type MigrateResult struct {
	Path         string `json:"path"`
	FromVersion  int    `json:"from_version"`
	ToVersion    int    `json:"to_version"`
	FileID       string `json:"file_id"`
	Generation   uint64 `json:"generation"`
	SlotCapacity uint32 `json:"slot_capacity"`
	KeySlots     int    `json:"key_slots"`
	BytesCopied  int64  `json:"bytes_copied"`
}

// peekVersion reports the format version a stream starts with, without
// consuming it.
func peekVersion(br *bufio.Reader) (int, error) {
	magic, err := br.Peek(len(magicV2))
	if err != nil {
		return 0, ErrNotSindook
	}
	switch string(magic) {
	case magicV1:
		return 1, nil
	case magicV2:
		return 2, nil
	case magicV3:
		return 3, nil
	default:
		return 0, ErrNotSindook
	}
}

// FileVersion reports the format version of a sealed file.
func FileVersion(r io.Reader) (int, error) {
	return peekVersion(bufio.NewReaderSize(r, len(magicV2)*2))
}

// writeArena renders both header slots of a v3 file into dst. Both hold the
// same generation, which is the steady state a scrubbed arena is always in.
func writeArena(dst io.Writer, sb *superblock, slot *headerSlot, fileKey []byte) error {
	if _, err := dst.Write(sb.encode()); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		slot.index = byte(i)
		buf, err := slot.encode(sb, fileKey)
		if err != nil {
			return err
		}
		if _, err := dst.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// newArenaFor builds the superblock and first-generation header for a file
// whose payload is already sealed under fileKey and contentNonce. Carrying
// both forward is what lets migration copy payload ciphertext verbatim: the
// payload key derivation is identical in every format version.
func newArenaFor(fileKey, contentNonce []byte, generation uint64, opts SealOptions, a ArenaOptions) (*superblock, *headerSlot, error) {
	capacity, err := slotCapacityFor(opts, a)
	if err != nil {
		return nil, nil, err
	}
	if len(a.PolicyDigest) != 0 && len(a.PolicyDigest) != policyDigestSize {
		return nil, nil, fmt.Errorf("sindook: policy digest must be %d bytes, got %d", policyDigestSize, len(a.PolicyDigest))
	}
	sb := &superblock{slotCapacity: capacity}
	if _, err := rand.Read(sb.fileID[:]); err != nil {
		return nil, nil, err
	}
	slot := &headerSlot{contentAlg: contentAlgStream64K, generation: generation}
	copy(slot.contentNonce[:], contentNonce)
	copy(slot.policyDigest[:], a.PolicyDigest)
	if slot.keySlots, err = buildKeySlots(fileKey, profileV3(sb.fileID[:]), opts); err != nil {
		return nil, nil, err
	}
	return sb, slot, nil
}

// resolveMigrationSlots fills in the slot set when the caller supplied none.
// A passphrase-only file can be migrated with just the passphrase that opened
// it; a file with recipient slots cannot, and says so.
func resolveMigrationSlots(opts SealOptions, info *Info, passphrase []byte) (SealOptions, error) {
	if len(opts.Recipients) > 0 || len(opts.Passphrases) > 0 {
		return opts, nil
	}
	for _, s := range info.Slots {
		if s.Type == SlotXWing {
			return opts, ErrRecipientsRequired
		}
	}
	if passphrase == nil {
		return opts, ErrRecipientsRequired
	}
	out := SealOptions{Passphrases: [][]byte{passphrase}, Argon: DefaultArgon2id}
	if len(info.Slots) > 0 && info.Slots[0].Argon != nil {
		out.Argon = *info.Slots[0].Argon
	}
	return out, nil
}

// migrateStream converts one sealed stream to v3. Payload ciphertext is
// copied byte for byte: it is never decrypted and never re-encrypted, so the
// content key is unchanged and anyone holding a copy of the old file is
// exactly as able to read it as before. Migration changes who can obtain the
// content key, not what the content key is.
// migrateBufSize holds the largest header any readable format can present, so
// the credential-free inspection below can always see a whole header. A v3
// file being moved to a different arena size is the demanding case: its arena
// alone can reach two megabytes.
const migrateBufSize = superblockSize + 2*maxSlotCapacity + chunkSize

func migrateStream(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte, opts SealOptions, a ArenaOptions) (*MigrateResult, error) {
	br := bufio.NewReaderSize(src, migrateBufSize)
	from, err := peekVersion(br)
	if err != nil {
		return nil, err
	}

	// Read the header twice: once without credentials to learn the slot
	// shape, once with them to recover the file key.
	head, err := br.Peek(br.Size())
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	info, err := Inspect(bytes.NewReader(head))
	if err != nil {
		return nil, err
	}
	if opts, err = resolveMigrationSlots(opts, info, passphrase); err != nil {
		return nil, err
	}

	fileKey, contentNonce, err := unlock(br, identity, passphrase)
	if err != nil {
		return nil, err
	}
	sb, slot, err := newArenaFor(fileKey, contentNonce, 1, opts, a)
	if err != nil {
		return nil, err
	}
	if err := writeArena(dst, sb, slot, fileKey); err != nil {
		return nil, err
	}
	copied, err := io.Copy(dst, br)
	if err != nil {
		return nil, err
	}
	return &MigrateResult{
		FromVersion:  from,
		ToVersion:    3,
		FileID:       hex.EncodeToString(sb.fileID[:]),
		Generation:   slot.generation,
		SlotCapacity: sb.slotCapacity,
		KeySlots:     len(slot.keySlots),
		BytesCopied:  copied,
	}, nil
}

// MigrateFile converts a sealed file to v3 in place, preserving permissions
// and modification time. It is a full-file rewrite because the payload has to
// move to make room for the arena; it is paid once, and every rotation after
// it is bounded.
func MigrateFile(ctx context.Context, path string, identity *xwing.PrivateKey, passphrase []byte, opts SealOptions, a ArenaOptions) (*MigrateResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".sindook-migrate-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	res, err := migrateStream(tmp, ctxReader{ctx: ctx, r: in}, identity, passphrase, opts, a)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Durability before the rename: a crash must not leave the original
	// replaced by a file whose contents never reached the disk.
	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		cleanup()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.Chtimes(tmp.Name(), info.ModTime(), info.ModTime()); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		cleanup()
		return nil, err
	}
	res.Path = path
	return res, nil
}

// rewrapV3Stream rotates a v3 file through a stream rather than in place, for
// the cases in-place cannot serve: writing to a different path, to stdout, or
// through ASCII armor. The file identifier and arena geometry are preserved,
// so the result is the same file at a higher generation.
func rewrapV3Stream(dst io.Writer, br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte, opts SealOptions, deep bool) error {
	// readArenaStream expects the magic already consumed, matching the read
	// path where unlock has taken it. Here the version was only peeked.
	if _, err := br.Discard(len(magicV3)); err != nil {
		return ErrNotSindook
	}
	a, err := readArenaStream(br)
	if err != nil {
		return err
	}
	u, err := unlockArena(a, identity, passphrase, openOptions{})
	if err != nil {
		return err
	}

	next := &headerSlot{
		contentAlg:   u.slot.contentAlg,
		generation:   a.highestGeneration() + 1,
		contentNonce: u.slot.contentNonce,
		policyDigest: u.slot.policyDigest,
	}
	fileKey := u.fileKey

	if deep {
		fileKey = make([]byte, fileKeySize)
		if _, err := rand.Read(fileKey); err != nil {
			return err
		}
		if _, err := rand.Read(next.contentNonce[:]); err != nil {
			return err
		}
	}
	if next.keySlots, err = buildKeySlots(fileKey, profileV3(a.sb.fileID[:]), opts); err != nil {
		return err
	}
	if err := writeArena(dst, a.sb, next, fileKey); err != nil {
		return err
	}

	if !deep {
		_, err := io.Copy(dst, br)
		return err
	}

	oldKey, err := u.payloadKey()
	if err != nil {
		return err
	}
	newKey, err := hkdf.Key(sha256.New, fileKey, next.contentNonce[:], payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(openPayload(pw, br, oldKey))
	}()
	return sealPayload(dst, pr, newKey)
}
