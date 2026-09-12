// Package box seals and opens sindook files. Format v2 wraps one random
// file key into multiple key slots (X-Wing recipients and Argon2id
// passphrases, the LUKS keyslot model), authenticates the whole header with
// a MAC keyed by the file key (the age approach), and seals the payload in
// authenticated 64 KiB chunks. Slots are length-prefixed so future
// algorithms can be added without breaking old readers. Files written by
// format v1 remain readable. The byte layout is specified in docs/FORMAT.md.
//
// This package is sindook's public library API, alongside xwing; its
// stability policy is documented in docs/COMPATIBILITY.md.
package box

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/internal/memguard"
	"github.com/ruddro-roy/sindook/xwing"
)

const (
	magicV1 = "SINDOOK1"
	magicV2 = "SINDOOK2"

	// v1 header mode bytes, kept for reading legacy files.
	modeV1Recipient  byte = 0x01
	modeV1Passphrase byte = 0x02

	// v2 slot types.
	SlotXWing      byte = 0x01
	SlotPassphrase byte = 0x02

	chunkSize     = 64 * 1024
	fileKeySize   = 32
	fileNonceSize = 16
	saltSize      = 16
	macSize       = 32

	maxSlots     = 32
	maxPassSlots = 4
	maxSlotBody  = 4096

	xwingSlotBody = xwing.CiphertextSize + fileKeySize + chacha20poly1305.Overhead
	passSlotBody  = 9 + saltSize + fileKeySize + chacha20poly1305.Overhead

	wrapInfoV1 = "sindook/v1/wrap"
	wrapInfoV2 = "sindook/v2/wrap"
	hdrMACInfo = "sindook/v2/hdr-mac"

	// payloadInfo is shared by both format versions: the payload construction
	// never changed, which is what lets Rewrap replace a header while leaving
	// payload bytes untouched.
	payloadInfo = "sindook/v1/payload"
)

// Argon2idParams travel inside passphrase slots so files remain openable
// after defaults change. Parsing enforces the caps below so a hostile header
// cannot demand unbounded work.
type Argon2idParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultArgon2id follows the second recommended parameter set of RFC 9106.
var DefaultArgon2id = Argon2idParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

const (
	maxArgonTime      = 64
	maxArgonMemoryKiB = 1024 * 1024
	maxArgonThreads   = 64
)

var (
	ErrNotSindook       = errors.New("sindook: not a sindook file")
	ErrNeedIdentity     = errors.New("sindook: file is sealed to a recipient, an identity file is required")
	ErrNeedPassphrase   = errors.New("sindook: file is sealed with a passphrase, use -p")
	ErrWrongKey         = errors.New("sindook: cannot unwrap file key: wrong identity or passphrase, or corrupted header")
	ErrHeaderTampered   = errors.New("sindook: header authentication failed: key slots were added, removed, or modified")
	ErrPayloadCorrupted = errors.New("sindook: payload authentication failed: file is corrupted or truncated")
)

func (p Argon2idParams) validate() error {
	if p.Time < 1 || p.Time > maxArgonTime ||
		p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxArgonMemoryKiB ||
		p.Threads < 1 || p.Threads > maxArgonThreads {
		return fmt.Errorf("sindook: argon2id parameters out of range (t=%d m=%d KiB p=%d)", p.Time, p.MemoryKiB, p.Threads)
	}
	return nil
}

// SealOptions describes the key slots of a sealed file: any number of X-Wing
// recipients and optionally passphrases, mixed freely.
type SealOptions struct {
	Recipients  [][]byte
	Passphrases [][]byte
	Argon       Argon2idParams
}

func (o SealOptions) validate() error {
	total := len(o.Recipients) + len(o.Passphrases)
	if total == 0 {
		return errors.New("sindook: at least one recipient or passphrase is required")
	}
	if total > maxSlots {
		return fmt.Errorf("sindook: at most %d key slots per file", maxSlots)
	}
	if len(o.Passphrases) > maxPassSlots {
		return fmt.Errorf("sindook: at most %d passphrase slots per file", maxPassSlots)
	}
	for _, r := range o.Recipients {
		if len(r) != xwing.PublicKeySize {
			return errors.New("sindook: malformed recipient public key")
		}
	}
	if len(o.Passphrases) > 0 {
		if err := o.Argon.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Seal encrypts src to dst with one slot per recipient and passphrase.
func Seal(dst io.Writer, src io.Reader, opts SealOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	fileKey := make([]byte, fileKeySize)
	defer memguard.Wipe(fileKey)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	fileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(fileNonce); err != nil {
		return err
	}
	if err := writeHeaderV2(dst, fileKey, fileNonce, nil, opts); err != nil {
		return err
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	defer memguard.Wipe(payloadKey)
	return sealPayload(dst, src, payloadKey)
}

// SealRecipient seals to a single recipient. Kept as a convenience wrapper.
func SealRecipient(dst io.Writer, src io.Reader, recipientPub []byte) error {
	return Seal(dst, src, SealOptions{Recipients: [][]byte{recipientPub}})
}

// SealPassphrase seals with a single passphrase slot.
func SealPassphrase(dst io.Writer, src io.Reader, passphrase []byte, p Argon2idParams) error {
	return Seal(dst, src, SealOptions{Passphrases: [][]byte{passphrase}, Argon: p})
}

// slotAAD binds a slot's wrap to this file and to the slot's own public
// parameters, so a slot cannot be transplanted or have its KDF downgraded.
func slotAAD(fileNonce []byte, slotType byte, public []byte) []byte {
	aad := make([]byte, 0, len(magicV2)+fileNonceSize+1+len(public))
	aad = append(aad, magicV2...)
	aad = append(aad, fileNonce...)
	aad = append(aad, slotType)
	return append(aad, public...)
}

func wrapSeal(wrapKey, fileKey, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	// The wrap nonce is all zero: every wrap key is single-use, derived from
	// a fresh KEM shared secret or a fresh random salt.
	return aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, aad), nil
}

func wrapOpen(wrapKey, wrapped, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), wrapped, aad)
}

func headerMAC(fileKey, fileNonce, header []byte) ([]byte, error) {
	macKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, hdrMACInfo, macSize)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, macKey)
	m.Write(header)
	return m.Sum(nil), nil
}

// writeHeaderV2 emits a v2 header: kept slots verbatim (copied forward by
// RewrapEdit), then fresh slots for opts.Recipients and opts.Passphrases.
// A kept slot needs no secret to be carried: its wrap is bound to the file
// nonce and its own public parameters, all of which travel inside the slot.
func writeHeaderV2(dst io.Writer, fileKey, fileNonce []byte, kept []parsedSlot, opts SealOptions) error {
	var hdr bytes.Buffer
	hdr.WriteString(magicV2)
	hdr.Write(fileNonce)
	hdr.WriteByte(byte(len(kept) + len(opts.Recipients) + len(opts.Passphrases)))

	appendSlot := func(slotType byte, body []byte) {
		hdr.WriteByte(slotType)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(body)))
		hdr.Write(l[:])
		hdr.Write(body)
	}

	for _, s := range kept {
		appendSlot(s.slotType, s.body)
	}

	for _, pub := range opts.Recipients {
		ss, kemCT, err := xwing.Encapsulate(pub)
		if err != nil {
			return err
		}
		wrapKey, err := hkdf.Key(sha256.New, ss, fileNonce, wrapInfoV2, chacha20poly1305.KeySize)
		if err != nil {
			memguard.Wipe(ss)
			return err
		}
		wrapped, err := wrapSeal(wrapKey, fileKey, slotAAD(fileNonce, SlotXWing, kemCT))
		if err != nil {
			memguard.Wipe(ss)
			memguard.Wipe(wrapKey)
			return err
		}
		appendSlot(SlotXWing, append(kemCT, wrapped...))
		memguard.Wipe(ss)
		memguard.Wipe(wrapKey)
		memguard.Wipe(wrapped)
	}

	for _, pass := range opts.Passphrases {
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		public := make([]byte, 0, 9+saltSize)
		public = binary.BigEndian.AppendUint32(public, opts.Argon.Time)
		public = binary.BigEndian.AppendUint32(public, opts.Argon.MemoryKiB)
		public = append(public, opts.Argon.Threads)
		public = append(public, salt...)
		wrapKey := argon2.IDKey(pass, salt, opts.Argon.Time, opts.Argon.MemoryKiB, opts.Argon.Threads, chacha20poly1305.KeySize)
		wrapped, err := wrapSeal(wrapKey, fileKey, slotAAD(fileNonce, SlotPassphrase, public))
		if err != nil {
			memguard.Wipe(wrapKey)
			return err
		}
		appendSlot(SlotPassphrase, append(public, wrapped...))
		memguard.Wipe(wrapKey)
		memguard.Wipe(wrapped)
	}

	mac, err := headerMAC(fileKey, fileNonce, hdr.Bytes())
	if err != nil {
		return err
	}
	if _, err := dst.Write(hdr.Bytes()); err != nil {
		return err
	}
	_, err = dst.Write(mac)
	return err
}

type parsedSlot struct {
	slotType byte
	body     []byte
}

// headerInfo is the parsed form of a sealed file's header, returned by
// unlock so RewrapEdit can carry surviving slots forward. slots is nil for
// v1 files, which hold a single implicit slot whose credential type is mode.
type headerInfo struct {
	version int
	mode    byte
	slots   []parsedSlot
}

// unlock reads a v1 or v2 header from br, recovers the file key with the
// given credentials, verifies header integrity, and leaves br positioned at
// the first payload byte.
func unlock(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) (fileKey, fileNonce []byte, hdr headerInfo, err error) {
	magic := make([]byte, len(magicV2))
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, nil, hdr, ErrNotSindook
	}
	switch string(magic) {
	case magicV1:
		return unlockV1(br, identity, passphrase)
	case magicV2:
		return unlockV2(br, identity, passphrase)
	default:
		return nil, nil, hdr, ErrNotSindook
	}
}

// trySlotXWing attempts to unwrap an X-Wing slot under id, returning the
// file key on success. A nil key without error means the slot belongs to a
// different recipient or is malformed.
func trySlotXWing(s parsedSlot, fileNonce []byte, id *xwing.PrivateKey) ([]byte, error) {
	if len(s.body) != xwingSlotBody {
		return nil, nil
	}
	kemCT := s.body[:xwing.CiphertextSize]
	ss, err := id.Decapsulate(kemCT)
	if err != nil {
		return nil, nil
	}
	defer memguard.Wipe(ss)
	wrapKey, err := hkdf.Key(sha256.New, ss, fileNonce, wrapInfoV2, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer memguard.Wipe(wrapKey)
	fk, err := wrapOpen(wrapKey, s.body[xwing.CiphertextSize:], slotAAD(fileNonce, SlotXWing, kemCT))
	if err != nil {
		return nil, nil
	}
	return fk, nil
}

// trySlotPass attempts to unwrap a passphrase slot under passphrase,
// returning the file key on success. A nil key means a different
// passphrase, a malformed slot, or out-of-cap KDF parameters.
func trySlotPass(s parsedSlot, fileNonce, passphrase []byte) []byte {
	if len(s.body) != passSlotBody {
		return nil
	}
	public := s.body[:9+saltSize]
	p := Argon2idParams{
		Time:      binary.BigEndian.Uint32(public[0:4]),
		MemoryKiB: binary.BigEndian.Uint32(public[4:8]),
		Threads:   public[8],
	}
	if err := p.validate(); err != nil {
		return nil
	}
	salt := public[9 : 9+saltSize]
	wrapKey := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
	defer memguard.Wipe(wrapKey)
	fk, err := wrapOpen(wrapKey, s.body[9+saltSize:], slotAAD(fileNonce, SlotPassphrase, public))
	if err != nil {
		return nil
	}
	return fk
}

func unlockV2(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) ([]byte, []byte, headerInfo, error) {
	var info headerInfo
	info.version = 2
	var hdr bytes.Buffer
	hdr.WriteString(magicV2)

	prefix := make([]byte, fileNonceSize+1)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, nil, info, ErrNotSindook
	}
	hdr.Write(prefix)
	fileNonce := append([]byte(nil), prefix[:fileNonceSize]...)
	count := int(prefix[fileNonceSize])
	if count < 1 || count > maxSlots {
		return nil, nil, info, ErrNotSindook
	}

	slots := make([]parsedSlot, 0, count)
	for i := 0; i < count; i++ {
		head := make([]byte, 3)
		if _, err := io.ReadFull(br, head); err != nil {
			return nil, nil, info, ErrNotSindook
		}
		bodyLen := int(binary.BigEndian.Uint16(head[1:3]))
		if bodyLen > maxSlotBody {
			return nil, nil, info, ErrNotSindook
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, nil, info, ErrNotSindook
		}
		hdr.Write(head)
		hdr.Write(body)
		slots = append(slots, parsedSlot{slotType: head[0], body: body})
	}
	info.slots = slots
	mac := make([]byte, macSize)
	if _, err := io.ReadFull(br, mac); err != nil {
		return nil, nil, info, ErrNotSindook
	}

	var sawXWing, sawPass bool
	var fileKey []byte
	for _, s := range slots {
		switch s.slotType {
		case SlotXWing:
			sawXWing = true
			if identity == nil || fileKey != nil {
				continue
			}
			fk, err := trySlotXWing(s, fileNonce, identity)
			if err != nil {
				return nil, nil, info, err
			}
			fileKey = fk
		case SlotPassphrase:
			sawPass = true
			if passphrase == nil || fileKey != nil {
				continue
			}
			fileKey = trySlotPass(s, fileNonce, passphrase)
		default:
			// Unknown slot type from a future version: unusable here but
			// still covered by the header MAC below.
		}
	}
	if fileKey == nil {
		if identity == nil && sawXWing {
			return nil, nil, info, ErrNeedIdentity
		}
		if passphrase == nil && sawPass {
			return nil, nil, info, ErrNeedPassphrase
		}
		return nil, nil, info, ErrWrongKey
	}

	wantMAC, err := headerMAC(fileKey, fileNonce, hdr.Bytes())
	if err != nil {
		return nil, nil, info, err
	}
	if !hmac.Equal(mac, wantMAC) {
		return nil, nil, info, ErrHeaderTampered
	}
	return fileKey, fileNonce, info, nil
}

func unlockV1(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) ([]byte, []byte, headerInfo, error) {
	info := headerInfo{version: 1}
	mode, err := br.ReadByte()
	if err != nil {
		return nil, nil, info, ErrNotSindook
	}
	info.mode = mode
	header := append([]byte(magicV1), mode)

	var wrapKey []byte
	switch mode {
	case modeV1Recipient:
		if identity == nil {
			return nil, nil, info, ErrNeedIdentity
		}
		rest := make([]byte, xwing.CiphertextSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, nil, info, ErrNotSindook
		}
		header = append(header, rest...)
		ss, err := identity.Decapsulate(rest[:xwing.CiphertextSize])
		if err != nil {
			return nil, nil, info, ErrWrongKey
		}
		wrapKey, err = hkdf.Key(sha256.New, ss, rest[xwing.CiphertextSize:], wrapInfoV1, chacha20poly1305.KeySize)
		if err != nil {
			return nil, nil, info, err
		}
	case modeV1Passphrase:
		if passphrase == nil {
			return nil, nil, info, ErrNeedPassphrase
		}
		rest := make([]byte, 9+saltSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, nil, info, ErrNotSindook
		}
		header = append(header, rest...)
		p := Argon2idParams{
			Time:      binary.BigEndian.Uint32(rest[0:4]),
			MemoryKiB: binary.BigEndian.Uint32(rest[4:8]),
			Threads:   rest[8],
		}
		if err := p.validate(); err != nil {
			return nil, nil, info, err
		}
		wrapKey = argon2.IDKey(passphrase, rest[9:9+saltSize], p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
	default:
		return nil, nil, info, fmt.Errorf("sindook: unknown v1 mode 0x%02x", mode)
	}
	fileNonce := append([]byte(nil), header[len(header)-fileNonceSize:]...)

	wrapped := make([]byte, fileKeySize+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(br, wrapped); err != nil {
		return nil, nil, info, ErrNotSindook
	}
	fileKey, err := wrapOpen(wrapKey, wrapped, header)
	if err != nil {
		memguard.Wipe(wrapKey)
		return nil, nil, info, ErrWrongKey
	}
	memguard.Wipe(wrapKey)
	return fileKey, fileNonce, info, nil
}

// Open decrypts src into dst using whichever credential matches a key slot.
func Open(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte) error {
	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)
	fileKey, fileNonce, _, err := unlock(br, identity, passphrase)
	if err != nil {
		return err
	}
	defer memguard.Wipe(fileKey)
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	defer memguard.Wipe(payloadKey)
	return openPayload(dst, br, payloadKey)
}

// Rewrap rewrites the key slots of a sealed file. In the default fast mode,
// the file key and payload bytes are carried over without decrypting or
// re-encrypting the payload, although the ciphertext is copied to dst. With
// deep=true the payload is re-encrypted under a fresh file key by streaming
// decrypt and re-encrypt, one chunk in memory at a time. Fast mode does not
// revoke a removed recipient who already held a copy of the old file. Deep
// mode makes the newly produced replacement inaccessible through the old
// file key, but cannot invalidate older copies. For edits that keep
// unmentioned slots instead of replacing the whole set, see RewrapEdit.
func Rewrap(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte, opts SealOptions, deep bool) error {
	if err := opts.validate(); err != nil {
		return err
	}
	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)
	fileKey, fileNonce, _, err := unlock(br, identity, passphrase)
	if err != nil {
		return err
	}

	if !deep {
		defer memguard.Wipe(fileKey)
		if err := writeHeaderV2(dst, fileKey, fileNonce, nil, opts); err != nil {
			return err
		}
		_, err := io.Copy(dst, br)
		return err
	}

	oldPayloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		memguard.Wipe(fileKey)
		return err
	}
	defer memguard.Wipe(fileKey)
	defer memguard.Wipe(oldPayloadKey)
	newFileKey := make([]byte, fileKeySize)
	defer memguard.Wipe(newFileKey)
	if _, err := rand.Read(newFileKey); err != nil {
		return err
	}
	newFileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(newFileNonce); err != nil {
		return err
	}
	if err := writeHeaderV2(dst, newFileKey, newFileNonce, nil, opts); err != nil {
		return err
	}
	newPayloadKey, err := hkdf.Key(sha256.New, newFileKey, newFileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	defer memguard.Wipe(newPayloadKey)
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.CloseWithError(openPayload(pw, br, oldPayloadKey))
	}()
	err = sealPayload(dst, pr, newPayloadKey)
	// sealPayload can return early on a dst error while openPayload is still
	// running, so unblock and join the pipe writer before wiping oldPayloadKey.
	pr.CloseWithError(err)
	<-done
	return err
}

// SlotEdit describes an incremental rewrite of a sealed file's key slots:
// which existing slots survive, which are removed, and which are appended.
// Kept slots are copied verbatim. A slot's wrap is bound to the file nonce
// and to its own public parameters, and both travel inside the slot, so a
// kept slot stays valid without knowing its secret. The payload is carried
// over unchanged, making every edit a fast-mode rewrap; rotating the file
// key needs Rewrap with deep=true, which discards every slot.
//
// Drop slots are numbered 1-based, matching Inspect's listing. Every drop
// selector must claim at least one slot: a selector that matches nothing
// fails the operation instead of silently writing an unchanged file. Kept
// slots keep their order and added slots follow them.
type SlotEdit struct {
	// KeepAll carries over every slot no drop selector claims. Without it
	// RewrapEdit degenerates to a fast-mode Rewrap of Add.
	KeepAll bool

	// DropSlots removes slots by number.
	DropSlots []int
	// DropPassSlots removes every passphrase-type slot.
	DropPassSlots bool
	// DropIdentities removes every X-Wing slot that opens under one of
	// these keys, including the identity that unlocked the file.
	DropIdentities []*xwing.PrivateKey
	// DropPassphrases removes every passphrase slot that opens under one of
	// these passphrases.
	DropPassphrases [][]byte

	// Add appends new slots after the kept ones.
	Add SealOptions
}

// RewrapEdit rewrites the key slots of a sealed file incrementally,
// preserving unmentioned slots instead of replacing the whole set. It
// shares Rewrap's fast-mode caveat: the file key and payload bytes carry
// over, so a removed recipient who kept a copy of the old file is not
// revoked. On a v1 file the single implicit slot cannot be carried
// verbatim; KeepAll instead re-creates the opening credential as a v2 slot,
// upgrading the file in place.
func RewrapEdit(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte, edit SlotEdit) error {
	hasDrop := len(edit.DropSlots) > 0 || edit.DropPassSlots ||
		len(edit.DropIdentities) > 0 || len(edit.DropPassphrases) > 0
	if hasDrop && !edit.KeepAll {
		return errors.New("sindook: drop selectors have no effect without KeepAll")
	}
	if !edit.KeepAll {
		return Rewrap(dst, src, identity, passphrase, edit.Add, false)
	}

	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)
	fileKey, fileNonce, hdr, err := unlock(br, identity, passphrase)
	if err != nil {
		return err
	}
	defer memguard.Wipe(fileKey)

	matchedIDs := make([]bool, len(edit.DropIdentities))
	matchedPass := make([]bool, len(edit.DropPassphrases))
	matchedPassType := false

	var kept []parsedSlot
	add := edit.Add
	if hdr.version == 1 {
		// A v1 file holds one implicit slot bound to the credential that
		// opened it, so a credential selector matches only when it is that
		// same credential.
		dropped := false
		for _, n := range edit.DropSlots {
			if n != 1 {
				return fmt.Errorf("sindook: no slot %d, the file has 1 slot", n)
			}
			dropped = true
		}
		switch hdr.mode {
		case modeV1Recipient:
			for j, d := range edit.DropIdentities {
				if bytes.Equal(d.PublicKey(), identity.PublicKey()) {
					matchedIDs[j] = true
					dropped = true
				}
			}
		case modeV1Passphrase:
			if edit.DropPassSlots {
				matchedPassType = true
				dropped = true
			}
			for j, q := range edit.DropPassphrases {
				if bytes.Equal(q, passphrase) {
					matchedPass[j] = true
					dropped = true
				}
			}
		}
		if !dropped {
			switch hdr.mode {
			case modeV1Recipient:
				add.Recipients = append([][]byte{identity.PublicKey()}, add.Recipients...)
			case modeV1Passphrase:
				add.Passphrases = append([][]byte{passphrase}, add.Passphrases...)
			}
		}
	} else {
		dropIndex := make(map[int]bool, len(edit.DropSlots))
		for _, n := range edit.DropSlots {
			if n < 1 || n > len(hdr.slots) {
				return fmt.Errorf("sindook: no slot %d, the file has %d slots", n, len(hdr.slots))
			}
			dropIndex[n] = true
		}
		for i, s := range hdr.slots {
			drop := dropIndex[i+1]
			switch s.slotType {
			case SlotXWing:
				for j, d := range edit.DropIdentities {
					fk, err := trySlotXWing(s, fileNonce, d)
					if err != nil {
						return err
					}
					if fk != nil {
						memguard.Wipe(fk)
						matchedIDs[j] = true
						drop = true
					}
				}
			case SlotPassphrase:
				if edit.DropPassSlots {
					matchedPassType = true
					drop = true
				}
				for j, q := range edit.DropPassphrases {
					if fk := trySlotPass(s, fileNonce, q); fk != nil {
						memguard.Wipe(fk)
						matchedPass[j] = true
						drop = true
					}
				}
			}
			if !drop {
				kept = append(kept, s)
			}
		}
	}
	if edit.DropPassSlots && !matchedPassType {
		return errors.New("sindook: no passphrase slot to drop")
	}
	for j := range matchedIDs {
		if !matchedIDs[j] {
			return fmt.Errorf("sindook: no slot opens under drop identity %d", j+1)
		}
	}
	for j := range matchedPass {
		if !matchedPass[j] {
			return fmt.Errorf("sindook: no slot opens under drop passphrase %d", j+1)
		}
	}

	if len(add.Passphrases) > 0 && add.Argon == (Argon2idParams{}) {
		add.Argon = DefaultArgon2id
	}
	if len(add.Recipients)+len(add.Passphrases) > 0 {
		if err := add.validate(); err != nil {
			return err
		}
	}
	passCount := len(add.Passphrases)
	for _, s := range kept {
		if s.slotType == SlotPassphrase {
			passCount++
		}
	}
	total := len(kept) + len(add.Recipients) + len(add.Passphrases)
	if total == 0 {
		return errors.New("sindook: rewrap would leave the file with no key slots")
	}
	if total > maxSlots {
		return fmt.Errorf("sindook: rewrap would leave %d key slots, at most %d allowed", total, maxSlots)
	}
	if passCount > maxPassSlots {
		return fmt.Errorf("sindook: rewrap would leave %d passphrase slots, at most %d allowed", passCount, maxPassSlots)
	}
	if err := writeHeaderV2(dst, fileKey, fileNonce, kept, add); err != nil {
		return err
	}
	_, err = io.Copy(dst, br)
	return err
}

// setNonce writes an 11-byte big-endian counter and a final-chunk flag into
// a 12-byte ChaCha20-Poly1305 nonce, the scheme used by age's STREAM variant.
func setNonce(nonce []byte, counter uint64, last bool) {
	for i := 0; i < 3; i++ {
		nonce[i] = 0
	}
	binary.BigEndian.PutUint64(nonce[3:11], counter)
	if last {
		nonce[11] = 0x01
	} else {
		nonce[11] = 0x00
	}
}

func sealPayload(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(src, chunkSize)
	buf := make([]byte, chunkSize)
	sealed := make([]byte, 0, chunkSize+aead.Overhead())
	defer memguard.Wipe(sealed[:cap(sealed)])
	nonce := make([]byte, chacha20poly1305.NonceSize)
	var counter uint64
	for {
		n, rerr := io.ReadFull(br, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		last := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if !last {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		setNonce(nonce, counter, last)
		sealed = aead.Seal(sealed[:0], nonce, buf[:n], nil)
		if _, err := dst.Write(sealed); err != nil {
			return err
		}
		counter++
		if last {
			return nil
		}
	}
}

func openPayload(dst io.Writer, br *bufio.Reader, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	sealed := make([]byte, chunkSize+aead.Overhead())
	defer memguard.Wipe(sealed[:cap(sealed)])
	plain := make([]byte, 0, chunkSize)
	defer memguard.Wipe(plain[:cap(plain)])
	nonce := make([]byte, chacha20poly1305.NonceSize)
	var counter uint64
	for {
		n, rerr := io.ReadFull(br, sealed)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		if n < aead.Overhead() {
			return ErrPayloadCorrupted
		}
		last := rerr == io.ErrUnexpectedEOF
		if rerr == nil {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		if rerr == io.EOF {
			return ErrPayloadCorrupted
		}
		setNonce(nonce, counter, last)
		pt, err := aead.Open(plain[:0], nonce, sealed[:n], nil)
		if err != nil {
			return ErrPayloadCorrupted
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		counter++
		if last {
			return nil
		}
	}
}
