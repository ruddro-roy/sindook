// Package box seals and opens sindook files: a self-describing header that
// wraps a random file key (via X-Wing to a recipient, or Argon2id from a
// passphrase), followed by the payload in authenticated 64 KiB chunks.
// The byte layout is specified in docs/FORMAT.md.
package box

import (
	"bufio"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/internal/xwing"
)

const (
	magic = "SINDOOK1"

	ModeRecipient  byte = 0x01
	ModePassphrase byte = 0x02

	chunkSize     = 64 * 1024
	fileKeySize   = 32
	fileNonceSize = 16
	saltSize      = 16

	wrapInfo    = "sindook/v1/wrap"
	payloadInfo = "sindook/v1/payload"
)

// Argon2idParams travel in passphrase-mode headers so files remain openable
// after defaults change. Open enforces the caps below to stop a hostile
// header from requesting gigabytes of memory.
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

// SealRecipient encrypts src to dst for the holder of recipientPub.
func SealRecipient(dst io.Writer, src io.Reader, recipientPub []byte) error {
	ss, kemCT, err := xwing.Encapsulate(recipientPub)
	if err != nil {
		return err
	}
	fileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(fileNonce); err != nil {
		return err
	}
	header := make([]byte, 0, len(magic)+1+xwing.CiphertextSize+fileNonceSize)
	header = append(header, magic...)
	header = append(header, ModeRecipient)
	header = append(header, kemCT...)
	header = append(header, fileNonce...)

	wrapKey, err := hkdf.Key(sha256.New, ss, fileNonce, wrapInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	return sealCommon(dst, src, header, wrapKey, fileNonce)
}

// SealPassphrase encrypts src to dst under a passphrase using Argon2id.
func SealPassphrase(dst io.Writer, src io.Reader, passphrase []byte, p Argon2idParams) error {
	if err := p.validate(); err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	fileNonce := make([]byte, fileNonceSize)
	if _, err := rand.Read(fileNonce); err != nil {
		return err
	}
	header := make([]byte, 0, len(magic)+1+9+saltSize+fileNonceSize)
	header = append(header, magic...)
	header = append(header, ModePassphrase)
	header = binary.BigEndian.AppendUint32(header, p.Time)
	header = binary.BigEndian.AppendUint32(header, p.MemoryKiB)
	header = append(header, p.Threads)
	header = append(header, salt...)
	header = append(header, fileNonce...)

	wrapKey := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
	return sealCommon(dst, src, header, wrapKey, fileNonce)
}

func sealCommon(dst io.Writer, src io.Reader, header, wrapKey, fileNonce []byte) error {
	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return err
	}
	// The wrap nonce is all zero: every wrap key is single-use, derived from
	// a fresh KEM shared secret or a fresh random salt.
	wrapped := wrapAEAD.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, header)

	if _, err := dst.Write(header); err != nil {
		return err
	}
	if _, err := dst.Write(wrapped); err != nil {
		return err
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	return sealPayload(dst, src, payloadKey)
}

// Open decrypts src into dst. Pass the identity for recipient-mode files or
// the passphrase for passphrase-mode files; the header says which is needed.
func Open(dst io.Writer, src io.Reader, identity *xwing.PrivateKey, passphrase []byte) error {
	br := bufio.NewReaderSize(src, chunkSize+chacha20poly1305.Overhead)

	header := make([]byte, len(magic)+1)
	if _, err := io.ReadFull(br, header); err != nil {
		return ErrNotSindook
	}
	if string(header[:len(magic)]) != magic {
		return ErrNotSindook
	}
	mode := header[len(magic)]

	var wrapKey []byte
	switch mode {
	case ModeRecipient:
		if identity == nil {
			return ErrNeedIdentity
		}
		rest := make([]byte, xwing.CiphertextSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return ErrNotSindook
		}
		header = append(header, rest...)
		kemCT := rest[:xwing.CiphertextSize]
		fileNonce := rest[xwing.CiphertextSize:]
		ss, err := identity.Decapsulate(kemCT)
		if err != nil {
			return ErrWrongKey
		}
		wrapKey, err = hkdf.Key(sha256.New, ss, fileNonce, wrapInfo, chacha20poly1305.KeySize)
		if err != nil {
			return err
		}
	case ModePassphrase:
		if passphrase == nil {
			return ErrNeedPassphrase
		}
		rest := make([]byte, 9+saltSize+fileNonceSize)
		if _, err := io.ReadFull(br, rest); err != nil {
			return ErrNotSindook
		}
		header = append(header, rest...)
		p := Argon2idParams{
			Time:      binary.BigEndian.Uint32(rest[0:4]),
			MemoryKiB: binary.BigEndian.Uint32(rest[4:8]),
			Threads:   rest[8],
		}
		if err := p.validate(); err != nil {
			return err
		}
		salt := rest[9 : 9+saltSize]
		wrapKey = argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
	default:
		return fmt.Errorf("sindook: unknown mode 0x%02x", mode)
	}
	fileNonce := header[len(header)-fileNonceSize:]

	wrapAEAD, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return err
	}
	wrapped := make([]byte, fileKeySize+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(br, wrapped); err != nil {
		return ErrNotSindook
	}
	fileKey, err := wrapAEAD.Open(nil, make([]byte, chacha20poly1305.NonceSize), wrapped, header)
	if err != nil {
		return ErrWrongKey
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		return err
	}
	return openPayload(dst, br, payloadKey)
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
