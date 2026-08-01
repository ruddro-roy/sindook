// Package box seals and opens sindook files. Format v2 wraps one random
// file key into multiple key slots (X-Wing recipients and Argon2id
// passphrases, the LUKS keyslot model), authenticates the whole header with
// a MAC keyed by the file key (the age approach), and seals the payload in
// authenticated 64 KiB chunks. Slots are length-prefixed so future
// algorithms can be added without breaking old readers. Files written by
// format v1 remain readable. The byte layout is specified in docs/FORMAT.md.
package box

import (
	"bufio"
	"bytes"
	"context"
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
	wrapInfoV3 = "sindook/v3/wrap"

	hdrMACInfo   = "sindook/v2/hdr-mac"
	hdrMACInfoV3 = "sindook/v3/hdr-mac"

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
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	fileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(fileNonce); err != nil {
		return err
	}
	if err := writeHeaderV2(dst, fileKey, fileNonce, opts); err != nil {
		return err
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
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

func writeHeaderV2(dst io.Writer, fileKey, fileNonce []byte, opts SealOptions) error {
	slots, err := buildKeySlots(fileKey, profileV2(fileNonce), opts)
	if err != nil {
		return err
	}

	var hdr bytes.Buffer
	hdr.WriteString(magicV2)
	hdr.Write(fileNonce)
	hdr.WriteByte(byte(len(slots)))
	hdr.Write(encodeKeySlots(slots))

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

// unlock reads a v1 or v2 header from br, recovers the file key with the
// given credentials, verifies header integrity, and leaves br positioned at
// the first payload byte.
func unlock(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) (fileKey, fileNonce []byte, err error) {
	magic := make([]byte, len(magicV2))
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, nil, ErrNotSindook
	}
	switch string(magic) {
	case magicV1:
		return unlockV1(br, identity, passphrase)
	case magicV2:
		return unlockV2(br, identity, passphrase)
	case magicV3:
		return unlockV3(br, identity, passphrase)
	default:
		return nil, nil, ErrNotSindook
	}
}

func unlockV2(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) ([]byte, []byte, error) {
	var hdr bytes.Buffer
	hdr.WriteString(magicV2)

	prefix := make([]byte, fileNonceSize+1)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, nil, ErrNotSindook
	}
	hdr.Write(prefix)
	fileNonce := append([]byte(nil), prefix[:fileNonceSize]...)
	count := int(prefix[fileNonceSize])
	if count < 1 || count > maxSlots {
		return nil, nil, ErrNotSindook
	}

	slots := make([]parsedSlot, 0, count)
	for i := 0; i < count; i++ {
		head := make([]byte, 3)
		if _, err := io.ReadFull(br, head); err != nil {
			return nil, nil, ErrNotSindook
		}
		bodyLen := int(binary.BigEndian.Uint16(head[1:3]))
		if bodyLen > maxSlotBody {
			return nil, nil, ErrNotSindook
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, nil, ErrNotSindook
		}
		hdr.Write(head)
		hdr.Write(body)
		slots = append(slots, parsedSlot{slotType: head[0], body: body})
	}
	mac := make([]byte, macSize)
	if _, err := io.ReadFull(br, mac); err != nil {
		return nil, nil, ErrNotSindook
	}

	fileKey, sawXWing, sawPass, err := openKeySlots(slots, profileV2(fileNonce), identity, passphrase)
	if err != nil {
		return nil, nil, err
	}
	if fileKey == nil {
		return nil, nil, credentialError(identity, passphrase, sawXWing, sawPass)
	}

	wantMAC, err := headerMAC(fileKey, fileNonce, hdr.Bytes())
	if err != nil {
		return nil, nil, err
	}
	if !hmac.Equal(mac, wantMAC) {
		return nil, nil, ErrHeaderTampered
	}
	return fileKey, fileNonce, nil
}

func unlockV1(br *bufio.Reader, identity *xwing.PrivateKey, passphrase []byte) ([]byte, []byte, error) {
	mode, err := br.ReadByte()
	if err != nil {
		return nil, nil, ErrNotSindook
	}
	header := append([]byte(magicV1), mode)

	var wrapKey []byte
	switch mode {
	case modeV1Recipient:
		if identity == nil {
			return nil, nil, ErrNeedIdentity
		}
		rest := make([]byte, xwing.CiphertextSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, nil, ErrNotSindook
		}
		header = append(header, rest...)
		ss, err := identity.Decapsulate(rest[:xwing.CiphertextSize])
		if err != nil {
			return nil, nil, ErrWrongKey
		}
		wrapKey, err = hkdf.Key(sha256.New, ss, rest[xwing.CiphertextSize:], wrapInfoV1, chacha20poly1305.KeySize)
		if err != nil {
			return nil, nil, err
		}
	case modeV1Passphrase:
		if passphrase == nil {
			return nil, nil, ErrNeedPassphrase
		}
		rest := make([]byte, 9+saltSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, nil, ErrNotSindook
		}
		header = append(header, rest...)
		p := Argon2idParams{
			Time:      binary.BigEndian.Uint32(rest[0:4]),
			MemoryKiB: binary.BigEndian.Uint32(rest[4:8]),
			Threads:   rest[8],
		}
		if err := p.validate(); err != nil {
			return nil, nil, err
		}
		wrapKey = argon2.IDKey(passphrase, rest[9:9+saltSize], p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
	default:
		return nil, nil, fmt.Errorf("sindook: unknown v1 mode 0x%02x", mode)
	}
	fileNonce := append([]byte(nil), header[len(header)-fileNonceSize:]...)

	wrapped := make([]byte, fileKeySize+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(br, wrapped); err != nil {
		return nil, nil, ErrNotSindook
	}
	fileKey, err := wrapOpen(wrapKey, wrapped, header)
	if err != nil {
		return nil, nil, ErrWrongKey
	}
	return fileKey, fileNonce, nil
}

// Open decrypts src into dst using whichever credential matches a key slot.
func Open(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte) error {
	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)
	fileKey, fileNonce, err := unlock(br, identity, passphrase)
	if err != nil {
		return err
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	return openPayload(dst, br, payloadKey)
}

// Rewrap rewrites the key slots of a sealed file. In the default fast mode
// the file key and payload bytes are carried over untouched, so the
// cryptographic work of a rotation is one header per file whatever the
// payload size and plaintext never exists anywhere. The payload ciphertext
// is still copied verbatim from src to dst, so total I/O scales with the
// payload; RewrapAt on a v3 file avoids that copy. With deep=true the payload is
// re-encrypted under a fresh file key by streaming decrypt and re-encrypt,
// one chunk in memory at a time. Fast mode does not retroactively revoke a
// removed recipient who already held a copy of the old file; deep mode does.
func Rewrap(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte, opts SealOptions, deep bool) error {
	if err := opts.validate(); err != nil {
		return err
	}
	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)
	// A v3 file rotates as a v3 file. Streaming through Rewrap must never
	// silently downgrade a bounded-rotation archive to a format that cannot
	// rotate in place.
	if v, verr := peekVersion(br); verr == nil && v == 3 {
		return rewrapV3Stream(dst, br, identity, passphrase, opts, deep)
	}
	fileKey, fileNonce, err := unlock(br, identity, passphrase)
	if err != nil {
		return err
	}

	if !deep {
		if err := writeHeaderV2(dst, fileKey, fileNonce, opts); err != nil {
			return err
		}
		_, err := io.Copy(dst, br)
		return err
	}

	oldPayloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	newFileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(newFileKey); err != nil {
		return err
	}
	newFileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(newFileNonce); err != nil {
		return err
	}
	if err := writeHeaderV2(dst, newFileKey, newFileNonce, opts); err != nil {
		return err
	}
	newPayloadKey, err := hkdf.Key(sha256.New, newFileKey, newFileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(openPayload(pw, br, oldPayloadKey))
	}()
	return sealPayload(dst, pr, newPayloadKey)
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

// ctxReader makes a long payload read cancellable. Verifying a hundred
// gigabyte archive should stop when the operator stops it, not when the file
// ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func openPayloadFrom(ctx context.Context, r io.Reader, dst io.Writer, key []byte) error {
	br := bufio.NewReaderSize(ctxReader{ctx: ctx, r: r}, chunkSize+chacha20poly1305.Overhead)
	return openPayload(dst, br, key)
}

func openPayload(dst io.Writer, br *bufio.Reader, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	sealed := make([]byte, chunkSize+aead.Overhead())
	plain := make([]byte, 0, chunkSize)
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
