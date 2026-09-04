package box

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/xwing"
)

func TestInspectV2(t *testing.T) {
	k1, _ := xwing.GenerateKey()
	k2, _ := xwing.GenerateKey()
	plain := bytes.Repeat([]byte("inspect"), 40_000) // spans multiple chunks
	var sealed bytes.Buffer
	err := Seal(&sealed, bytes.NewReader(plain), SealOptions{
		Recipients:  [][]byte{k1.PublicKey(), k2.PublicKey()},
		Passphrases: [][]byte{[]byte("pw")},
		Argon:       Argon2idParams{Time: 1, MemoryKiB: 64, Threads: 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	info, err := Inspect(bytes.NewReader(sealed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 2 || len(info.Slots) != 3 {
		t.Fatalf("got version %d, %d slots", info.Version, len(info.Slots))
	}
	if info.Slots[0].Type != SlotXWing || info.Slots[1].Type != SlotXWing {
		t.Fatalf("first two slots should be x-wing: %+v", info.Slots)
	}
	pass := info.Slots[2]
	if pass.Type != SlotPassphrase || pass.Argon == nil {
		t.Fatalf("passphrase slot not parsed: %+v", pass)
	}
	if pass.Argon.Time != 1 || pass.Argon.MemoryKiB != 64 || pass.Argon.Threads != 2 {
		t.Fatalf("argon params mismatch: %+v", pass.Argon)
	}
	payload := int64(sealed.Len()) - info.HeaderSize
	if got := PlaintextSize(payload); got != int64(len(plain)) {
		t.Fatalf("PlaintextSize = %d, want %d", got, len(plain))
	}
}

func TestInspectV1Fixtures(t *testing.T) {
	for _, tc := range []struct {
		file     string
		slotType byte
		hasArgon bool
	}{
		{"testdata/v1-recipient.sindook", modeV1Recipient, false},
		{"testdata/v1-passphrase.sindook", modeV1Passphrase, true},
	} {
		raw, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		info, err := Inspect(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if info.Version != 1 || len(info.Slots) != 1 || info.Slots[0].Type != tc.slotType {
			t.Fatalf("%s: %+v", tc.file, info)
		}
		if (info.Slots[0].Argon != nil) != tc.hasArgon {
			t.Fatalf("%s: argon presence mismatch", tc.file)
		}
		payload := int64(len(raw)) - info.HeaderSize
		if got := PlaintextSize(payload); got < 0 {
			t.Fatalf("%s: implausible payload size %d", tc.file, payload)
		}
	}
}

func TestInspectRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("not a sindook file at all"),
		[]byte("SINDOOK2"), // truncated after magic
		append([]byte("SINDOOK2"), make([]byte, 16)...), // truncated before count
	} {
		if _, err := Inspect(bytes.NewReader(in)); err == nil {
			t.Fatalf("garbage accepted: %q", in)
		}
	}
}

// A v1 passphrase file whose argon2id parameters exceed the caps is not
// inspectable: unlockV1 rejects such headers outright, so Inspect must too
// instead of presenting the hostile KDF claim as sane metadata.
func TestInspectRejectsHostileArgonV1(t *testing.T) {
	buf := []byte(magicV1)
	buf = append(buf, modeV1Passphrase)
	buf = binary.BigEndian.AppendUint32(buf, 0x22222222) // Time
	buf = binary.BigEndian.AppendUint32(buf, 0x22222222) // MemoryKiB
	buf = append(buf, 40)                                // Threads
	buf = append(buf, make([]byte, saltSize+fileNonceSize+fileKeySize+chacha20poly1305.Overhead)...)
	if _, err := Inspect(bytes.NewReader(buf)); err == nil {
		t.Fatal("Inspect accepted out-of-range argon2id parameters")
	}
}

// In v2 the same hostile parameters affect one slot among possibly many, and
// unlockV2 merely skips that slot, so Inspect must still describe the file
// while withholding the slot's argon2id claim.
func TestInspectWithholdsHostileArgonV2(t *testing.T) {
	body := make([]byte, passSlotBody)
	binary.BigEndian.PutUint32(body[0:4], 0x22222222) // Time
	binary.BigEndian.PutUint32(body[4:8], 0x22222222) // MemoryKiB
	body[8] = 40                                      // Threads
	buf := []byte(magicV2)
	buf = append(buf, make([]byte, fileNonceSize)...) // file nonce
	buf = append(buf, 1)                              // slot count
	buf = append(buf, SlotPassphrase)
	buf = binary.BigEndian.AppendUint16(buf, uint16(passSlotBody))
	buf = append(buf, body...)
	buf = append(buf, make([]byte, macSize)...)
	info, err := Inspect(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("Inspect rejected an otherwise valid v2 header: %v", err)
	}
	if len(info.Slots) != 1 || info.Slots[0].Type != SlotPassphrase {
		t.Fatalf("passphrase slot missing: %+v", info.Slots)
	}
	if info.Slots[0].Argon != nil {
		t.Fatalf("Inspect exposed out-of-range argon2id parameters: %+v", info.Slots[0].Argon)
	}
}

func TestPlaintextSize(t *testing.T) {
	const full = chunkSize + 16
	for _, tc := range []struct{ payload, want int64 }{
		{16, 0},                    // empty file: one empty final chunk
		{17, 1},                    //
		{full, chunkSize},          // exactly one full chunk
		{full + 16, chunkSize},     // full chunk plus empty final: writer never emits this, but size is unambiguous
		{full + 17, chunkSize + 1}, //
		{2*full + 40, 2*chunkSize + 24},
		{15, -1},       // shorter than one tag
		{full + 3, -1}, // final chunk shorter than a tag
	} {
		if got := PlaintextSize(tc.payload); got != tc.want {
			t.Fatalf("PlaintextSize(%d) = %d, want %d", tc.payload, got, tc.want)
		}
	}
}
