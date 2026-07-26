package box

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

// slotProfile is the domain separation a format version applies to its key
// slots: the magic that opens every slot's associated data, the salt mixed
// into wrap-key derivation, and the HKDF info string. v2 salts with the file
// nonce, v3 with the file identifier, and the two info strings differ, so a
// slot lifted from one format cannot be replayed into the other.
type slotProfile struct {
	magic    string
	salt     []byte
	wrapInfo string
}

func profileV2(fileNonce []byte) slotProfile {
	return slotProfile{magic: magicV2, salt: fileNonce, wrapInfo: wrapInfoV2}
}

func profileV3(fileID []byte) slotProfile {
	return slotProfile{magic: magicV3, salt: fileID, wrapInfo: wrapInfoV3}
}

// slotAAD binds a slot's wrap to this file and to the slot's own public
// parameters, so a slot cannot be transplanted or have its KDF downgraded.
func (p slotProfile) slotAAD(slotType byte, public []byte) []byte {
	aad := make([]byte, 0, len(p.magic)+len(p.salt)+1+len(public))
	aad = append(aad, p.magic...)
	aad = append(aad, p.salt...)
	aad = append(aad, slotType)
	return append(aad, public...)
}

// buildKeySlots wraps fileKey once per recipient and once per passphrase.
// Recipients come first, matching the order every sindook writer has used.
func buildKeySlots(fileKey []byte, p slotProfile, opts SealOptions) ([]parsedSlot, error) {
	slots := make([]parsedSlot, 0, len(opts.Recipients)+len(opts.Passphrases))

	for _, pub := range opts.Recipients {
		ss, kemCT, err := xwing.Encapsulate(pub)
		if err != nil {
			return nil, err
		}
		wrapKey, err := hkdf.Key(sha256.New, ss, p.salt, p.wrapInfo, chacha20poly1305.KeySize)
		if err != nil {
			return nil, err
		}
		wrapped, err := wrapSeal(wrapKey, fileKey, p.slotAAD(SlotXWing, kemCT))
		if err != nil {
			return nil, err
		}
		slots = append(slots, parsedSlot{slotType: SlotXWing, body: append(kemCT, wrapped...)})
	}

	for _, pass := range opts.Passphrases {
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		public := make([]byte, 0, 9+saltSize)
		public = binary.BigEndian.AppendUint32(public, opts.Argon.Time)
		public = binary.BigEndian.AppendUint32(public, opts.Argon.MemoryKiB)
		public = append(public, opts.Argon.Threads)
		public = append(public, salt...)
		wrapKey := argon2.IDKey(pass, salt, opts.Argon.Time, opts.Argon.MemoryKiB, opts.Argon.Threads, chacha20poly1305.KeySize)
		wrapped, err := wrapSeal(wrapKey, fileKey, p.slotAAD(SlotPassphrase, public))
		if err != nil {
			return nil, err
		}
		slots = append(slots, parsedSlot{slotType: SlotPassphrase, body: append(public, wrapped...)})
	}
	return slots, nil
}

// openKeySlots tries every slot the supplied credentials could open and
// returns the file key from the first that unwraps. sawXWing and sawPass
// report which slot kinds the header offered, so a caller that recovered
// nothing can say which credential was missing rather than "wrong key".
func openKeySlots(slots []parsedSlot, p slotProfile, identity *xwing.PrivateKey, passphrase []byte) (fileKey []byte, sawXWing, sawPass bool, err error) {
	for _, s := range slots {
		switch s.slotType {
		case SlotXWing:
			sawXWing = true
			if identity == nil || fileKey != nil || len(s.body) != xwingSlotBody {
				continue
			}
			kemCT := s.body[:xwing.CiphertextSize]
			ss, derr := identity.Decapsulate(kemCT)
			if derr != nil {
				continue
			}
			wrapKey, kerr := hkdf.Key(sha256.New, ss, p.salt, p.wrapInfo, chacha20poly1305.KeySize)
			if kerr != nil {
				return nil, sawXWing, sawPass, kerr
			}
			if fk, oerr := wrapOpen(wrapKey, s.body[xwing.CiphertextSize:], p.slotAAD(SlotXWing, kemCT)); oerr == nil {
				fileKey = fk
			}
		case SlotPassphrase:
			sawPass = true
			if passphrase == nil || fileKey != nil || len(s.body) != passSlotBody {
				continue
			}
			public := s.body[:9+saltSize]
			ap := Argon2idParams{
				Time:      binary.BigEndian.Uint32(public[0:4]),
				MemoryKiB: binary.BigEndian.Uint32(public[4:8]),
				Threads:   public[8],
			}
			if verr := ap.validate(); verr != nil {
				continue
			}
			salt := public[9 : 9+saltSize]
			wrapKey := argon2.IDKey(passphrase, salt, ap.Time, ap.MemoryKiB, ap.Threads, chacha20poly1305.KeySize)
			if fk, oerr := wrapOpen(wrapKey, s.body[9+saltSize:], p.slotAAD(SlotPassphrase, public)); oerr == nil {
				fileKey = fk
			}
		default:
			// Unknown slot type from a future version: unusable here but
			// still covered by the header authentication tag.
		}
	}
	return fileKey, sawXWing, sawPass, nil
}

// credentialError names the credential a caller was missing, so the CLI can
// say "use -p" instead of "wrong key" when the file only has passphrase slots.
func credentialError(identity *xwing.PrivateKey, passphrase []byte, sawXWing, sawPass bool) error {
	if identity == nil && sawXWing {
		return ErrNeedIdentity
	}
	if passphrase == nil && sawPass {
		return ErrNeedPassphrase
	}
	return ErrWrongKey
}

// encodeKeySlots writes the [type][length][body] framing shared by v2 and v3.
func encodeKeySlots(slots []parsedSlot) []byte {
	out := make([]byte, 0, 64)
	for _, s := range slots {
		out = append(out, s.slotType)
		out = binary.BigEndian.AppendUint16(out, uint16(len(s.body)))
		out = append(out, s.body...)
	}
	return out
}

// decodeKeySlots parses exactly count slots and requires them to fill buf
// completely. A surplus or shortfall means the header lied about its own
// length, which is a malformed slot rather than a credential problem.
func decodeKeySlots(buf []byte, count int) ([]parsedSlot, error) {
	if count < 1 || count > maxSlots {
		return nil, ErrMalformedSlot
	}
	slots := make([]parsedSlot, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		if off+3 > len(buf) {
			return nil, ErrMalformedSlot
		}
		bodyLen := int(binary.BigEndian.Uint16(buf[off+1 : off+3]))
		if bodyLen > maxSlotBody || off+3+bodyLen > len(buf) {
			return nil, ErrMalformedSlot
		}
		slots = append(slots, parsedSlot{
			slotType: buf[off],
			body:     append([]byte(nil), buf[off+3:off+3+bodyLen]...),
		})
		off += 3 + bodyLen
	}
	if off != len(buf) {
		return nil, ErrMalformedSlot
	}
	return slots, nil
}

// encodedKeySlotsLen is the wire size of a slot set, used to size an arena
// before any cryptography runs.
func encodedKeySlotsLen(opts SealOptions) int {
	return len(opts.Recipients)*(3+xwingSlotBody) + len(opts.Passphrases)*(3+passSlotBody)
}
