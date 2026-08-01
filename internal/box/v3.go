// Format v3 reserves a fixed header arena so the payload always begins at a
// stable offset. That is what lets a rotation touch a bounded number of bytes
// instead of copying the payload to move a variable-length header. The arena
// holds two independently authenticated header slots carrying a monotonic
// generation number, so a rotation can write one, verify it, and only then
// overwrite the other: a crash at any point leaves at least one authorized
// policy readable. docs/FORMAT-V3.md is the normative specification.
package box

import (
	"bufio"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

const (
	magicV3   = "SINDOOK3"
	slotMagic = "SLT3"

	formatV3 uint16 = 3

	superblockSize = 64
	arenaOffset    = 64

	// slotFixed is the size of a header slot's fixed prefix, before key
	// slots; slotMinUsed adds the trailing MAC.
	slotFixed   = 84
	slotMinUsed = slotFixed + macSize

	minSlotCapacity     = 4096
	maxSlotCapacity     = 1 << 20
	capacityGranularity = 4096

	fileIDSize       = 16
	policyDigestSize = 32

	// contentAlgStream64K is ChaCha20-Poly1305 with the STREAM chunking used
	// by every sindook format version. Cryptographic behaviour is selected by
	// this identifier, never inferred from the format version.
	contentAlgStream64K byte = 1

	// criticalFlagMask marks the feature-flag bits a reader must understand.
	// Bits above it are advisory and may be ignored.
	criticalFlagMask uint32 = 0x0000ffff

	// defaultReserveRecipients is the growth headroom a new arena gets when
	// the caller does not choose a capacity: enough for four more X-Wing
	// recipients, so the common "add a colleague" rotation never hits a
	// capacity error on a file sealed with defaults.
	defaultReserveRecipients = 4
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	ErrMalformedSlot      = errors.New("sindook: malformed header slot")
	ErrNoReadableHeader   = errors.New("sindook: no structurally complete header slot: the header arena is damaged")
	ErrStaleGeneration    = errors.New("sindook: header changed since it was read: another writer rotated this file")
	ErrUnsupportedFeature = errors.New("sindook: file requires a format feature this build does not support")
	ErrNotV3              = errors.New("sindook: not a format v3 file: bounded rotation needs v3, run sindook migrate")
)

// CapacityError reports a header that does not fit the arena reserved when
// the file was sealed. Growing the arena moves the payload, so it is an
// explicit migration rather than something a rotation does silently.
type CapacityError struct {
	Required  int
	Available int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("sindook: header needs %d bytes but the file reserved %d: re-seal with a larger arena (sindook migrate -header-capacity %d)",
		e.Required, e.Available, roundCapacity(e.Required))
}

// ArenaOptions controls the fixed header arena of a new v3 file.
type ArenaOptions struct {
	// SlotCapacity fixes the per-slot size in bytes. Zero derives it from
	// the initial slot set plus ReserveRecipients of headroom.
	SlotCapacity uint32
	// ReserveRecipients is how many additional X-Wing recipients the arena
	// should have room for. Zero means the default of four; negative means
	// no headroom at all.
	ReserveRecipients int
	// PolicyDigest is the canonical digest of the policy that produced this
	// slot set, or nil for none. Only the digest is stored: human identities
	// and comments stay out of ciphertext metadata.
	PolicyDigest []byte
}

func roundCapacity(need int) int {
	c := ((need + capacityGranularity - 1) / capacityGranularity) * capacityGranularity
	if c < minSlotCapacity {
		c = minSlotCapacity
	}
	return c
}

// slotCapacityFor sizes the arena before any cryptography runs, so an
// impossible request fails immediately rather than after a key exchange.
func slotCapacityFor(opts SealOptions, a ArenaOptions) (uint32, error) {
	need := slotMinUsed + encodedKeySlotsLen(opts)
	if a.SlotCapacity != 0 {
		if a.SlotCapacity < minSlotCapacity || a.SlotCapacity > maxSlotCapacity || a.SlotCapacity%capacityGranularity != 0 {
			return 0, fmt.Errorf("sindook: header capacity must be a multiple of %d in [%d, %d], got %d",
				capacityGranularity, minSlotCapacity, maxSlotCapacity, a.SlotCapacity)
		}
		if need > int(a.SlotCapacity) {
			return 0, &CapacityError{Required: need, Available: int(a.SlotCapacity)}
		}
		return a.SlotCapacity, nil
	}
	reserve := a.ReserveRecipients
	switch {
	case reserve == 0:
		reserve = defaultReserveRecipients
	case reserve < 0:
		reserve = 0
	}
	c := roundCapacity(need + reserve*(3+xwingSlotBody))
	if c > maxSlotCapacity {
		c = maxSlotCapacity
	}
	if need > c {
		return 0, &CapacityError{Required: need, Available: c}
	}
	return uint32(c), nil
}

// superblock is written once at seal time and never modified. Rotation
// depends on that: the payload offset must not move.
type superblock struct {
	flags        uint32
	fileID       [fileIDSize]byte
	slotCapacity uint32
}

func (s *superblock) payloadOffset() int64 {
	return arenaOffset + 2*int64(s.slotCapacity)
}

func (s *superblock) arenaSize() int64 { return 2 * int64(s.slotCapacity) }

func (s *superblock) slotOffset(index int) int64 {
	return arenaOffset + int64(index)*int64(s.slotCapacity)
}

func (s *superblock) encode() []byte {
	b := make([]byte, superblockSize)
	copy(b[0:8], magicV3)
	binary.BigEndian.PutUint16(b[8:10], formatV3)
	binary.BigEndian.PutUint16(b[10:12], superblockSize)
	binary.BigEndian.PutUint32(b[12:16], s.flags)
	copy(b[16:32], s.fileID[:])
	binary.BigEndian.PutUint32(b[32:36], arenaOffset)
	binary.BigEndian.PutUint32(b[36:40], s.slotCapacity)
	binary.BigEndian.PutUint64(b[40:48], uint64(s.payloadOffset()))
	binary.BigEndian.PutUint32(b[48:52], superblockCRC(b))
	return b
}

// superblockCRC checksums the superblock with its own CRC field read as zero,
// which is how a reader can verify a field that is part of what it covers.
func superblockCRC(b []byte) uint32 {
	c := crc32.Checksum(b[:48], castagnoli)
	c = crc32.Update(c, castagnoli, zeroed4)
	return crc32.Update(c, castagnoli, b[52:])
}

func parseSuperblock(b []byte) (*superblock, error) {
	if len(b) != superblockSize || string(b[0:8]) != magicV3 {
		return nil, ErrNotSindook
	}
	if binary.BigEndian.Uint16(b[8:10]) != formatV3 || binary.BigEndian.Uint16(b[10:12]) != superblockSize {
		return nil, ErrNotSindook
	}
	if binary.BigEndian.Uint32(b[48:52]) != superblockCRC(b) {
		return nil, ErrNotSindook
	}

	s := &superblock{flags: binary.BigEndian.Uint32(b[12:16]), slotCapacity: binary.BigEndian.Uint32(b[36:40])}
	copy(s.fileID[:], b[16:32])
	if s.flags&criticalFlagMask != 0 {
		return nil, ErrUnsupportedFeature
	}
	if binary.BigEndian.Uint32(b[32:36]) != arenaOffset {
		return nil, ErrNotSindook
	}
	if s.slotCapacity < minSlotCapacity || s.slotCapacity > maxSlotCapacity || s.slotCapacity%capacityGranularity != 0 {
		return nil, ErrNotSindook
	}
	if binary.BigEndian.Uint64(b[40:48]) != uint64(s.payloadOffset()) {
		return nil, ErrNotSindook
	}
	return s, nil
}

// headerSlot is one of the two logical headers in the arena.
type headerSlot struct {
	index        byte
	contentAlg   byte
	generation   uint64
	flags        uint32
	contentNonce [fileNonceSize]byte
	policyDigest [policyDigestSize]byte
	keySlots     []parsedSlot

	// usedLen and scrubbed are observations about the bytes a slot was
	// parsed from, not part of its logical content.
	usedLen  int
	scrubbed bool
}

// slotMACKey is derived from the file key, so only a credential holder can
// authenticate a header, and from the file identifier, so a header cannot be
// replayed into another file.
func slotMACKey(fileKey []byte, sb *superblock) ([]byte, error) {
	return hkdf.Key(sha256.New, fileKey, sb.fileID[:], hdrMACInfoV3, macSize)
}

// zeroed4 is the placeholder both the CRC and the MAC substitute for the CRC
// field, so neither has to copy a slot to blank four bytes.
var zeroed4 = make([]byte, 4)

// crcField is the offset of the CRC field within a slot; it is skipped by the
// checksum that computes it and by the MAC that would otherwise depend on it.
const crcField = 24

// writeCRCSkipped feeds a region to w with the CRC field replaced by zeros,
// without copying the region. Slots run to a megabyte, so the copy this
// avoids is the largest allocation in the read path.
func writeCRCSkipped(w io.Writer, region []byte) {
	w.Write(region[:crcField])
	w.Write(zeroed4)
	w.Write(region[crcField+4:])
}

// slotCRC checksums slot[0:used] with the CRC field itself read as zero.
func slotCRC(buf []byte, used int) uint32 {
	c := crc32.Checksum(buf[:crcField], castagnoli)
	c = crc32.Update(c, castagnoli, zeroed4)
	return crc32.Update(c, castagnoli, buf[crcField+4:used])
}

// slotMAC covers the superblock as well as the slot, binding the arena
// geometry and file identifier to every header that claims to describe them.
// The authenticated region is everything before the MAC itself, with the CRC
// field zeroed: the CRC is computed last, over bytes that include the MAC, so
// authenticating it too would make each depend on the other.
func slotMAC(fileKey []byte, sb *superblock, buf []byte, used int) ([]byte, error) {
	key, err := slotMACKey(fileKey, sb)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(sb.encode())
	writeCRCSkipped(m, buf[:used-macSize])
	return m.Sum(nil), nil
}

// encode renders a slot into a full-capacity buffer. Every byte past the
// used length is zero, so a completed rotation cannot leave a superseded
// wrapped key behind in the arena.
func (h *headerSlot) encode(sb *superblock, fileKey []byte) ([]byte, error) {
	body := encodeKeySlots(h.keySlots)
	used := slotFixed + len(body) + macSize
	if used > int(sb.slotCapacity) {
		return nil, &CapacityError{Required: used, Available: int(sb.slotCapacity)}
	}
	if len(h.keySlots) < 1 || len(h.keySlots) > maxSlots {
		return nil, fmt.Errorf("sindook: header needs 1 to %d key slots, got %d", maxSlots, len(h.keySlots))
	}

	buf := make([]byte, sb.slotCapacity)
	copy(buf[0:4], slotMagic)
	binary.BigEndian.PutUint16(buf[4:6], formatV3)
	buf[6] = h.index
	buf[7] = h.contentAlg
	binary.BigEndian.PutUint64(buf[8:16], h.generation)
	binary.BigEndian.PutUint32(buf[16:20], uint32(used))
	binary.BigEndian.PutUint32(buf[20:24], sb.slotCapacity)
	// buf[24:28] is the CRC, left zero while it is computed over itself.
	binary.BigEndian.PutUint32(buf[28:32], h.flags)
	copy(buf[32:48], h.contentNonce[:])
	copy(buf[48:80], h.policyDigest[:])
	binary.BigEndian.PutUint16(buf[80:82], uint16(len(h.keySlots)))
	copy(buf[slotFixed:], body)

	mac, err := slotMAC(fileKey, sb, buf, used)
	if err != nil {
		return nil, err
	}
	copy(buf[used-macSize:used], mac)
	binary.BigEndian.PutUint32(buf[crcField:crcField+4], slotCRC(buf, used))

	h.usedLen = used
	h.scrubbed = true
	return buf, nil
}

// parseSlot performs every check that does not need a key. A slot that
// survives it is "structurally complete" and eligible for generation
// selection; whether it is authentic is only known after a credential
// recovers the file key and verifyMAC succeeds.
func parseSlot(sb *superblock, index int, buf []byte) (*headerSlot, error) {
	if len(buf) != int(sb.slotCapacity) {
		return nil, ErrMalformedSlot
	}
	if string(buf[0:4]) != slotMagic || binary.BigEndian.Uint16(buf[4:6]) != formatV3 {
		return nil, ErrMalformedSlot
	}
	if int(buf[6]) != index {
		return nil, ErrMalformedSlot
	}
	if binary.BigEndian.Uint32(buf[20:24]) != sb.slotCapacity {
		return nil, ErrMalformedSlot
	}
	used := int(binary.BigEndian.Uint32(buf[16:20]))
	if used < slotMinUsed || used > int(sb.slotCapacity) {
		return nil, ErrMalformedSlot
	}

	if binary.BigEndian.Uint32(buf[crcField:crcField+4]) != slotCRC(buf, used) {
		return nil, ErrMalformedSlot
	}

	h := &headerSlot{
		index:      buf[6],
		contentAlg: buf[7],
		generation: binary.BigEndian.Uint64(buf[8:16]),
		flags:      binary.BigEndian.Uint32(buf[28:32]),
		usedLen:    used,
	}
	if h.flags&criticalFlagMask != 0 {
		return nil, ErrUnsupportedFeature
	}
	if h.contentAlg != contentAlgStream64K {
		return nil, ErrUnsupportedFeature
	}
	copy(h.contentNonce[:], buf[32:48])
	copy(h.policyDigest[:], buf[48:80])

	slots, err := decodeKeySlots(buf[slotFixed:used-macSize], int(binary.BigEndian.Uint16(buf[80:82])))
	if err != nil {
		return nil, err
	}
	h.keySlots = slots
	h.scrubbed = allZero(buf[used:])
	return h, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (h *headerSlot) storedMAC(buf []byte) []byte { return buf[h.usedLen-macSize : h.usedLen] }

func (h *headerSlot) verifyMAC(sb *superblock, fileKey, buf []byte) error {
	want, err := slotMAC(fileKey, sb, buf, h.usedLen)
	if err != nil {
		return err
	}
	if !hmac.Equal(h.storedMAC(buf), want) {
		return ErrHeaderTampered
	}
	return nil
}

// arena is the parsed state of both header slots. A slot that failed
// structural parsing is nil here, and its parse error is kept so a file with
// two damaged slots can explain why rather than only that.
type arena struct {
	sb    *superblock
	raw   []byte
	slots [2]*headerSlot
	errs  [2]error
}

func parseArena(sb *superblock, raw []byte) (*arena, error) {
	if int64(len(raw)) != sb.arenaSize() {
		return nil, ErrNotSindook
	}
	a := &arena{sb: sb, raw: raw}
	c := int(sb.slotCapacity)
	for i := range a.slots {
		a.slots[i], a.errs[i] = parseSlot(sb, i, raw[i*c:(i+1)*c])
	}
	return a, nil
}

func (a *arena) slotBytes(index int) []byte {
	c := int(a.sb.slotCapacity)
	return a.raw[index*c : (index+1)*c]
}

// order returns the indexes of structurally complete slots, highest
// generation first, ties broken toward slot 0.
func (a *arena) order() []int {
	var out []int
	for i, s := range a.slots {
		if s != nil {
			out = append(out, i)
		}
	}
	if len(out) == 2 && a.slots[out[1]].generation > a.slots[out[0]].generation {
		out[0], out[1] = out[1], out[0]
	}
	return out
}

// highestGeneration covers every structurally complete slot, including one
// that is not the active header. A rotation numbers itself above all of them
// so an interrupted predecessor can never have its generation reused.
func (a *arena) highestGeneration() uint64 {
	var g uint64
	for _, s := range a.slots {
		if s != nil && s.generation > g {
			g = s.generation
		}
	}
	return g
}

// scrubbed reports whether the arena holds exactly one policy. It is false
// after an interrupted rotation, when a superseded header is still present.
func (a *arena) scrubbed() bool {
	for i, s := range a.slots {
		if s == nil || !s.scrubbed {
			return false
		}
		if a.slots[0] != nil && a.slots[1] != nil && a.slots[i].generation != a.slots[0].generation {
			return false
		}
	}
	return true
}

// openOptions selects which generation a reader is allowed to use.
type openOptions struct {
	// allowSuperseded lets the reader fall back to a lower generation when
	// the supplied credential cannot open the selected one. It exists only
	// for the explicit recover command: a normal open must never do this,
	// because falling back hands access back to an identity that was just
	// removed.
	allowSuperseded bool
}

type v3Unlocked struct {
	sb      *superblock
	arena   *arena
	slot    *headerSlot
	index   int
	fileKey []byte
}

// unlockArena recovers the file key from the highest generation the caller is
// permitted to use, then authenticates that header before anything else in
// the file is trusted.
func unlockArena(a *arena, identity *xwing.PrivateKey, passphrase []byte, o openOptions) (*v3Unlocked, error) {
	candidates := a.order()
	if len(candidates) == 0 {
		if a.errs[0] != nil && errors.Is(a.errs[0], ErrUnsupportedFeature) {
			return nil, a.errs[0]
		}
		if a.errs[1] != nil && errors.Is(a.errs[1], ErrUnsupportedFeature) {
			return nil, a.errs[1]
		}
		return nil, ErrNoReadableHeader
	}
	if !o.allowSuperseded {
		candidates = candidates[:1]
	}

	profile := profileV3(a.sb.fileID[:])
	var sawXWing, sawPass bool
	for _, i := range candidates {
		slot := a.slots[i]
		fileKey, x, p, err := openKeySlots(slot.keySlots, profile, identity, passphrase)
		if err != nil {
			return nil, err
		}
		sawXWing = sawXWing || x
		sawPass = sawPass || p
		if fileKey == nil {
			continue
		}
		if err := slot.verifyMAC(a.sb, fileKey, a.slotBytes(i)); err != nil {
			return nil, err
		}
		return &v3Unlocked{sb: a.sb, arena: a, slot: slot, index: i, fileKey: fileKey}, nil
	}
	return nil, credentialError(identity, passphrase, sawXWing, sawPass)
}

func (u *v3Unlocked) payloadKey() ([]byte, error) {
	return hkdf.Key(sha256.New, u.fileKey, u.slot.contentNonce[:], payloadInfo, chacha20poly1305.KeySize)
}

// SealV3 writes a format v3 file: superblock, header arena, payload.
func SealV3(dst io.Writer, src io.Reader, opts SealOptions, a ArenaOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	capacity, err := slotCapacityFor(opts, a)
	if err != nil {
		return err
	}
	if len(a.PolicyDigest) != 0 && len(a.PolicyDigest) != policyDigestSize {
		return fmt.Errorf("sindook: policy digest must be %d bytes, got %d", policyDigestSize, len(a.PolicyDigest))
	}

	sb := &superblock{slotCapacity: capacity}
	if _, err := rand.Read(sb.fileID[:]); err != nil {
		return err
	}
	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	slot := &headerSlot{contentAlg: contentAlgStream64K, generation: 1}
	if _, err := rand.Read(slot.contentNonce[:]); err != nil {
		return err
	}
	copy(slot.policyDigest[:], a.PolicyDigest)
	if slot.keySlots, err = buildKeySlots(fileKey, profileV3(sb.fileID[:]), opts); err != nil {
		return err
	}

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

	payloadKey, err := hkdf.Key(sha256.New, fileKey, slot.contentNonce[:], payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	return sealPayload(dst, src, payloadKey)
}

// readArenaStream reads a superblock and arena from a stream whose magic has
// already been consumed, so v3 files open from pipes and armored input just
// like every earlier format.
func readArenaStream(br *bufio.Reader) (*arena, error) {
	sbBuf := make([]byte, superblockSize)
	copy(sbBuf[0:8], magicV3)
	if _, err := io.ReadFull(br, sbBuf[8:]); err != nil {
		return nil, ErrNotSindook
	}
	sb, err := parseSuperblock(sbBuf)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, sb.arenaSize())
	if _, err := io.ReadFull(br, raw); err != nil {
		return nil, ErrNotSindook
	}
	return parseArena(sb, raw)
}

func unlockV3(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) ([]byte, []byte, error) {
	a, err := readArenaStream(br)
	if err != nil {
		return nil, nil, err
	}
	u, err := unlockArena(a, identity, passphrase, openOptions{})
	if err != nil {
		return nil, nil, err
	}
	return u.fileKey, u.slot.contentNonce[:], nil
}
