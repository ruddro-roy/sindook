package box

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
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

	// Arena is present only for format v3.
	Arena *ArenaInfo `json:"arena,omitempty"`
}

// HeaderInfo describes one of a v3 file's two header slots. A slot that
// failed structural parsing reports Present false and why, which is how an
// interrupted rotation becomes visible without any credential.
type HeaderInfo struct {
	Index        int        `json:"index"`
	Present      bool       `json:"present"`
	Error        string     `json:"error,omitempty"`
	Generation   uint64     `json:"generation,omitempty"`
	PolicyDigest string     `json:"policy_digest,omitempty"`
	UsedBytes    int        `json:"used_bytes,omitempty"`
	Scrubbed     bool       `json:"scrubbed"`
	Slots        []SlotInfo `json:"slots,omitempty"`
}

// ArenaInfo is the v3 header arena as a reader sees it before presenting any
// credential. Everything here is a claim until a credential verifies the
// header MAC.
type ArenaInfo struct {
	FileID        string       `json:"file_id"`
	SlotCapacity  uint32       `json:"slot_capacity"`
	ArenaBytes    int64        `json:"arena_bytes"`
	PayloadOffset int64        `json:"payload_offset"`
	Active        int          `json:"active_slot"`
	Generation    uint64       `json:"generation"`
	Scrubbed      bool         `json:"scrubbed"`
	Headers       []HeaderInfo `json:"headers"`
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
	case magicV3:
		a, err := readArenaStream(br)
		if err != nil {
			return nil, err
		}
		return arenaInfo(a), nil
	default:
		return nil, ErrNotSindook
	}
}

// InspectAt reads only the header arena of a v3 file, so inspecting an
// archive costs the same whatever its size.
func InspectAt(r io.ReaderAt) (*Info, error) {
	a, err := readArenaAt(r)
	if err != nil {
		return nil, err
	}
	return arenaInfo(a), nil
}

func keySlotInfo(slots []parsedSlot) []SlotInfo {
	out := make([]SlotInfo, 0, len(slots))
	for _, s := range slots {
		si := SlotInfo{Type: s.slotType, Body: len(s.body)}
		if s.slotType == SlotPassphrase && len(s.body) == passSlotBody {
			si.Argon = &Argon2idParams{
				Time:      binary.BigEndian.Uint32(s.body[0:4]),
				MemoryKiB: binary.BigEndian.Uint32(s.body[4:8]),
				Threads:   s.body[8],
			}
		}
		out = append(out, si)
	}
	return out
}

func arenaInfo(a *arena) *Info {
	ai := &ArenaInfo{
		FileID:        hex.EncodeToString(a.sb.fileID[:]),
		SlotCapacity:  a.sb.slotCapacity,
		ArenaBytes:    a.sb.arenaSize(),
		PayloadOffset: a.sb.payloadOffset(),
		Active:        -1,
		Scrubbed:      a.scrubbed(),
	}
	for i, s := range a.slots {
		h := HeaderInfo{Index: i}
		if s == nil {
			if a.errs[i] != nil {
				h.Error = a.errs[i].Error()
			}
			ai.Headers = append(ai.Headers, h)
			continue
		}
		h.Present = true
		h.Generation = s.generation
		h.PolicyDigest = digestString(s.policyDigest[:])
		h.UsedBytes = s.usedLen
		h.Scrubbed = s.scrubbed
		h.Slots = keySlotInfo(s.keySlots)
		ai.Headers = append(ai.Headers, h)
	}

	info := &Info{Version: 3, HeaderSize: a.sb.payloadOffset(), Arena: ai}
	if order := a.order(); len(order) > 0 {
		ai.Active = order[0]
		ai.Generation = a.slots[order[0]].generation
		info.Slots = ai.Headers[order[0]].Slots
	}
	return info
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
