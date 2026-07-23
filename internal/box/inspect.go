package box

import (
	"bufio"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

// SlotInfo describes one key slot without unlocking it.
type SlotInfo struct {
	Type  byte            `json:"type"`
	Body  int             `json:"body_size"`
	Argon *Argon2idParams `json:"argon2id,omitempty"`
}

// Info is the public metadata of a sealed file: everything a holder of the
// ciphertext can already see. Inspect reveals nothing an attacker with the
// file does not have.
type Info struct {
	Version    int        `json:"version"`
	HeaderSize int64      `json:"header_size"`
	Slots      []SlotInfo `json:"slots"`
}

// Inspect parses a v1 or v2 header from r without credentials. It applies
// the same structural caps as unlocking, but cannot verify the header MAC:
// slot metadata is honest only for files that later open successfully.
func Inspect(r io.Reader) (*Info, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(magicV2))
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, ErrNotSindook
	}
	switch string(magic) {
	case magicV1:
		return inspectV1(br)
	case magicV2:
		return inspectV2(br)
	default:
		return nil, ErrNotSindook
	}
}

func inspectV2(br *bufio.Reader) (*Info, error) {
	prefix := make([]byte, fileNonceSize+1)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, ErrNotSindook
	}
	count := int(prefix[fileNonceSize])
	if count < 1 || count > maxSlots {
		return nil, ErrNotSindook
	}
	info := &Info{Version: 2, HeaderSize: int64(len(magicV2) + fileNonceSize + 1)}
	for i := 0; i < count; i++ {
		head := make([]byte, 3)
		if _, err := io.ReadFull(br, head); err != nil {
			return nil, ErrNotSindook
		}
		bodyLen := int(binary.BigEndian.Uint16(head[1:3]))
		if bodyLen > maxSlotBody {
			return nil, ErrNotSindook
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, ErrNotSindook
		}
		s := SlotInfo{Type: head[0], Body: bodyLen}
		if s.Type == SlotPassphrase && bodyLen == passSlotBody {
			s.Argon = &Argon2idParams{
				Time:      binary.BigEndian.Uint32(body[0:4]),
				MemoryKiB: binary.BigEndian.Uint32(body[4:8]),
				Threads:   body[8],
			}
		}
		info.Slots = append(info.Slots, s)
		info.HeaderSize += int64(3 + bodyLen)
	}
	mac := make([]byte, macSize)
	if _, err := io.ReadFull(br, mac); err != nil {
		return nil, ErrNotSindook
	}
	info.HeaderSize += macSize
	return info, nil
}

func inspectV1(br *bufio.Reader) (*Info, error) {
	mode, err := br.ReadByte()
	if err != nil {
		return nil, ErrNotSindook
	}
	s := SlotInfo{Type: mode}
	var bodyLen int
	switch mode {
	case modeV1Recipient:
		bodyLen = xwing.CiphertextSize + fileNonceSize
		if _, err := io.CopyN(io.Discard, br, int64(bodyLen)); err != nil {
			return nil, ErrNotSindook
		}
	case modeV1Passphrase:
		bodyLen = 9 + saltSize + fileNonceSize
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, ErrNotSindook
		}
		s.Argon = &Argon2idParams{
			Time:      binary.BigEndian.Uint32(body[0:4]),
			MemoryKiB: binary.BigEndian.Uint32(body[4:8]),
			Threads:   body[8],
		}
	default:
		return nil, ErrNotSindook
	}
	wrapped := make([]byte, fileKeySize+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(br, wrapped); err != nil {
		return nil, ErrNotSindook
	}
	s.Body = bodyLen + len(wrapped)
	return &Info{
		Version:    1,
		HeaderSize: int64(len(magicV1) + 1 + s.Body),
		Slots:      []SlotInfo{s},
	}, nil
}

// PlaintextSize returns the exact plaintext length of a well-formed sealed
// payload of payloadLen bytes, or -1 if no valid payload has that length.
func PlaintextSize(payloadLen int64) int64 {
	const full = chunkSize + chacha20poly1305.Overhead
	if payloadLen < chacha20poly1305.Overhead {
		return -1
	}
	chunks := (payloadLen + full - 1) / full
	last := payloadLen - (chunks-1)*full
	if last < chacha20poly1305.Overhead {
		return -1
	}
	return payloadLen - chunks*chacha20poly1305.Overhead
}
