package box

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ruddro-roy/sindook/internal/memguard"
	"github.com/ruddro-roy/sindook/xwing"
)

// Small parameters keep the Argon2id tests fast; validity is still enforced.
var testArgon = Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}

// Header sizes of v2 files with a single slot, per docs/FORMAT.md.
const (
	v2PassHeader  = 25 + 3 + passSlotBody + macSize
	v2XWingHeader = 25 + 3 + xwingSlotBody + macSize
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newIdentity(t *testing.T) *xwing.PrivateKey {
	t.Helper()
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealTo(t *testing.T, plain []byte, opts SealOptions) []byte {
	t.Helper()
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(plain), opts); err != nil {
		t.Fatal(err)
	}
	return sealed.Bytes()
}

func openWith(t *testing.T, blob []byte, id *xwing.PrivateKey, pass []byte) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := Open(&out, bytes.NewReader(blob), id, pass)
	return out.Bytes(), err
}

func roundTripSizes() []int {
	return []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 2*chunkSize + 513}
}

func TestRecipientRoundTrip(t *testing.T) {
	k := newIdentity(t)
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		out, err := openWith(t, sealTo(t, plain, SealOptions{Recipients: [][]byte{k.PublicKey()}}), k, nil)
		if err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	for _, n := range roundTripSizes() {
		plain := randomBytes(t, n)
		blob := sealTo(t, plain, SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})
		out, err := openWith(t, blob, nil, pass)
		if err != nil {
			t.Fatalf("n=%d: open: %v", n, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestMultiRecipient(t *testing.T) {
	k1, k2, k3, stranger := newIdentity(t), newIdentity(t), newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300)
	blob := sealTo(t, plain, SealOptions{
		Recipients: [][]byte{k1.PublicKey(), k2.PublicKey(), k3.PublicKey()},
	})
	for i, k := range []*xwing.PrivateKey{k1, k2, k3} {
		out, err := openWith(t, blob, k, nil)
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("recipient %d: plaintext mismatch", i)
		}
	}
	if _, err := openWith(t, blob, stranger, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("stranger: got %v, want ErrWrongKey", err)
	}
}

func TestMixedSlots(t *testing.T) {
	k := newIdentity(t)
	plain := randomBytes(t, 300)
	blob := sealTo(t, plain, SealOptions{
		Recipients:  [][]byte{k.PublicKey()},
		Passphrases: [][]byte{[]byte("rescue")},
		Argon:       testArgon,
	})
	if out, err := openWith(t, blob, k, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("identity path: %v", err)
	}
	if out, err := openWith(t, blob, nil, []byte("rescue")); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("passphrase path: %v", err)
	}
}

func TestV1Fixtures(t *testing.T) {
	seed, err := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	if err != nil {
		t.Fatal(err)
	}
	id, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("sindook v1 golden fixture\n")

	rec, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := openWith(t, rec, id, nil); err != nil || !bytes.Equal(out, want) {
		t.Fatalf("v1 recipient fixture: %v", err)
	}

	pw, err := os.ReadFile("testdata/v1-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := openWith(t, pw, nil, []byte("golden")); err != nil || !bytes.Equal(out, want) {
		t.Fatalf("v1 passphrase fixture: %v", err)
	}
}

func TestRewrapFast(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 2*chunkSize+513)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	var rewrapped bytes.Buffer
	err := Rewrap(&rewrapped, bytes.NewReader(old), k1, nil,
		SealOptions{Recipients: [][]byte{k2.PublicKey()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	blob := rewrapped.Bytes()

	if out, err := openWith(t, blob, k2, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("new recipient: %v", err)
	}
	if _, err := openWith(t, blob, k1, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("removed recipient: got %v, want ErrWrongKey", err)
	}
	// Fast mode must carry payload bytes over verbatim.
	if !bytes.Equal(old[v2XWingHeader:], blob[v2XWingHeader:]) {
		t.Fatal("fast rewrap modified payload bytes")
	}
}

func TestRewrapFastUpgradesV1(t *testing.T) {
	seed, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	oldID, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	newID := newIdentity(t)
	v1, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}

	var upgraded bytes.Buffer
	err = Rewrap(&upgraded, bytes.NewReader(v1), oldID, nil,
		SealOptions{Recipients: [][]byte{newID.PublicKey()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(upgraded.Bytes(), []byte(magicV2)) {
		t.Fatal("upgraded file is not format v2")
	}
	out, err := openWith(t, upgraded.Bytes(), newID, nil)
	if err != nil || !bytes.Equal(out, []byte("sindook v1 golden fixture\n")) {
		t.Fatalf("upgraded v1 file: %v", err)
	}
}

func TestRewrapDeep(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 2*chunkSize+513)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	var rewrapped bytes.Buffer
	err := Rewrap(&rewrapped, bytes.NewReader(old), k1, nil,
		SealOptions{Recipients: [][]byte{k2.PublicKey()}}, true)
	if err != nil {
		t.Fatal(err)
	}
	blob := rewrapped.Bytes()

	if out, err := openWith(t, blob, k2, nil); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("deep rewrap open: %v", err)
	}
	if bytes.Equal(old[v2XWingHeader:], blob[v2XWingHeader:]) {
		t.Fatal("deep rewrap left payload bytes unchanged")
	}
}

func rewrapEdit(t *testing.T, blob []byte, id *xwing.PrivateKey, pass []byte, edit SlotEdit) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := RewrapEdit(&out, bytes.NewReader(blob), id, pass, edit)
	return out.Bytes(), err
}

// slotRecord returns the raw bytes of the nth (1-based) slot record in a
// v2 file: type byte, length prefix, and body.
func slotRecord(t *testing.T, blob []byte, n int) []byte {
	t.Helper()
	off := 25
	for i := 1; i <= n; i++ {
		l := 3 + (int(blob[off+1])<<8 | int(blob[off+2]))
		if i == n {
			return blob[off : off+l]
		}
		off += l
	}
	t.Fatalf("file has no slot %d", n)
	return nil
}

func mustOpen(t *testing.T, blob []byte, id *xwing.PrivateKey, pass []byte, plain []byte) {
	t.Helper()
	out, err := openWith(t, blob, id, pass)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("plaintext mismatch")
	}
}

func mustFailOpen(t *testing.T, blob []byte, id *xwing.PrivateKey, pass []byte) {
	t.Helper()
	if _, err := openWith(t, blob, id, pass); err == nil {
		t.Fatal("open succeeded, want failure")
	}
}

func TestRewrapEditKeepAdd(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	blob, err := rewrapEdit(t, old, k1, nil, SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Recipients: [][]byte{k2.PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, k1, nil, plain)
	mustOpen(t, blob, k2, nil, plain)
	// The kept slot is copied verbatim and the payload is untouched.
	if !bytes.Equal(slotRecord(t, old, 1), slotRecord(t, blob, 1)) {
		t.Fatal("kept slot bytes changed")
	}
	newHeader := 25 + 2*(3+xwingSlotBody) + macSize
	if !bytes.Equal(old[v2XWingHeader:], blob[newHeader:]) {
		t.Fatal("payload bytes changed")
	}
}

func TestRewrapEditKeepOrder(t *testing.T) {
	k1, k2, k3 := newIdentity(t), newIdentity(t), newIdentity(t)
	old := sealTo(t, randomBytes(t, 100), SealOptions{
		Recipients: [][]byte{k1.PublicKey(), k2.PublicKey()},
	})
	blob, err := rewrapEdit(t, old, k2, nil, SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Recipients: [][]byte{k3.PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slotRecord(t, old, 1), slotRecord(t, blob, 1)) ||
		!bytes.Equal(slotRecord(t, old, 2), slotRecord(t, blob, 2)) {
		t.Fatal("kept slots lost their order")
	}
	for _, k := range []*xwing.PrivateKey{k1, k2, k3} {
		if _, err := openWith(t, blob, k, nil); err != nil {
			t.Fatalf("recipient: %v", err)
		}
	}
}

func TestRewrapEditDropSlot(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey(), k2.PublicKey()}})

	blob, err := rewrapEdit(t, old, k1, nil, SlotEdit{KeepAll: true, DropSlots: []int{1}})
	if err != nil {
		t.Fatal(err)
	}
	mustFailOpen(t, blob, k1, nil)
	mustOpen(t, blob, k2, nil, plain)
	if info, err := Inspect(bytes.NewReader(blob)); err != nil || len(info.Slots) != 1 {
		t.Fatalf("slots: %v %v", info, err)
	}
}

func TestRewrapEditDropIdentity(t *testing.T) {
	k1, k2, stranger := newIdentity(t), newIdentity(t), newIdentity(t)
	plain := randomBytes(t, 300)
	old := sealTo(t, plain, SealOptions{Recipients: [][]byte{k1.PublicKey(), k2.PublicKey()}})

	// Drop another identity's slot while opening with k1.
	blob, err := rewrapEdit(t, old, k1, nil, SlotEdit{KeepAll: true, DropIdentities: []*xwing.PrivateKey{k2}})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, k1, nil, plain)
	mustFailOpen(t, blob, k2, nil)

	// Drop the very identity used to unlock, handing the file off to k2.
	blob, err = rewrapEdit(t, old, k1, nil, SlotEdit{KeepAll: true, DropIdentities: []*xwing.PrivateKey{k1}})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, k2, nil, plain)
	mustFailOpen(t, blob, k1, nil)

	// A key that opens no slot fails the edit rather than writing an
	// unchanged file.
	if _, err := rewrapEdit(t, old, k1, nil, SlotEdit{KeepAll: true, DropIdentities: []*xwing.PrivateKey{stranger}}); err == nil {
		t.Fatal("unmatched drop identity accepted")
	}
}

func TestRewrapEditDropPassSlots(t *testing.T) {
	k := newIdentity(t)
	pass := []byte("rescue")
	plain := randomBytes(t, 300)
	old := sealTo(t, plain, SealOptions{
		Recipients:  [][]byte{k.PublicKey()},
		Passphrases: [][]byte{pass},
		Argon:       testArgon,
	})

	blob, err := rewrapEdit(t, old, k, nil, SlotEdit{KeepAll: true, DropPassSlots: true})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, k, nil, plain)
	mustFailOpen(t, blob, nil, pass)

	// Keeping while adding preserves the passphrase slot without knowing
	// the passphrase.
	blob, err = rewrapEdit(t, old, k, nil, SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Recipients: [][]byte{newIdentity(t).PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, nil, pass, plain)

	// The selector must match something.
	recOnly := sealTo(t, plain, SealOptions{Recipients: [][]byte{k.PublicKey()}})
	if _, err := rewrapEdit(t, recOnly, k, nil, SlotEdit{KeepAll: true, DropPassSlots: true}); err == nil {
		t.Fatal("unmatched -drop-pass-slots accepted")
	}
}

func TestRewrapEditDropPassphrase(t *testing.T) {
	p1, p2 := []byte("first"), []byte("second")
	plain := randomBytes(t, 300)
	old := sealTo(t, plain, SealOptions{Passphrases: [][]byte{p1, p2}, Argon: testArgon})

	// Unlock with p1, drop the slot p2 opens.
	blob, err := rewrapEdit(t, old, nil, p1, SlotEdit{KeepAll: true, DropPassphrases: [][]byte{p2}})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, nil, p1, plain)
	mustFailOpen(t, blob, nil, p2)

	if _, err := rewrapEdit(t, old, nil, p1, SlotEdit{KeepAll: true, DropPassphrases: [][]byte{[]byte("nope")}}); err == nil {
		t.Fatal("unmatched drop passphrase accepted")
	}
}

func TestRewrapEditErrors(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	old := sealTo(t, randomBytes(t, 100), SealOptions{Recipients: [][]byte{k1.PublicKey()}})

	// Drops without keep have nothing to apply to.
	if _, err := rewrapEdit(t, old, k1, nil, SlotEdit{DropSlots: []int{1}}); err == nil {
		t.Fatal("drop without KeepAll accepted")
	}
	// Out-of-range slot number.
	if _, err := rewrapEdit(t, old, k1, nil, SlotEdit{KeepAll: true, DropSlots: []int{2}}); err == nil {
		t.Fatal("out-of-range drop accepted")
	}
	// Dropping the only slot leaves a file nobody can open.
	var out bytes.Buffer
	err := RewrapEdit(&out, bytes.NewReader(old), k1, nil, SlotEdit{KeepAll: true, DropIdentities: []*xwing.PrivateKey{k1}})
	if err == nil {
		t.Fatal("drop-to-empty accepted")
	}
	if out.Len() != 0 {
		t.Fatal("partial output written on failed edit")
	}
	// A kept set plus additions cannot exceed the slot cap.
	many := [][]byte{k1.PublicKey()}
	for i := 0; i < maxSlots-1; i++ {
		many = append(many, newIdentity(t).PublicKey())
	}
	full := sealTo(t, []byte("x"), SealOptions{Recipients: many})
	overflow := SealOptions{Recipients: [][]byte{k2.PublicKey(), newIdentity(t).PublicKey()}}
	if _, err := rewrapEdit(t, full, k1, nil, SlotEdit{KeepAll: true, Add: overflow}); err == nil {
		t.Fatal("slot cap not enforced on edit")
	}
	// The same holds for the passphrase cap: 4 kept + 1 added.
	passes := make([][]byte, maxPassSlots)
	for i := range passes {
		passes[i] = []byte{byte('a' + i)}
	}
	passFull := sealTo(t, []byte("x"), SealOptions{Passphrases: passes, Argon: testArgon})
	_, err = rewrapEdit(t, passFull, nil, passes[0], SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Passphrases: [][]byte{[]byte("z")}, Argon: testArgon},
	})
	if err == nil {
		t.Fatal("passphrase slot cap not enforced on edit")
	}
}

func TestRewrapEditV1(t *testing.T) {
	seed, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	v1ID, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("sindook v1 golden fixture\n")

	rec, err := os.ReadFile("testdata/v1-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	// Bare keep upgrades the file to v2 while preserving access.
	blob, err := rewrapEdit(t, rec, v1ID, nil, SlotEdit{KeepAll: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte(magicV2)) {
		t.Fatal("kept v1 file did not become v2")
	}
	mustOpen(t, blob, v1ID, nil, want)

	// Keep + add preserves the opener and appends the new recipient.
	k2 := newIdentity(t)
	blob, err = rewrapEdit(t, rec, v1ID, nil, SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Recipients: [][]byte{k2.PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, v1ID, nil, want)
	mustOpen(t, blob, k2, nil, want)

	// Dropping the implicit slot while adding a recipient hands the v1
	// file off entirely.
	blob, err = rewrapEdit(t, rec, v1ID, nil, SlotEdit{
		KeepAll:   true,
		DropSlots: []int{1},
		Add:       SealOptions{Recipients: [][]byte{k2.PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustFailOpen(t, blob, v1ID, nil)
	mustOpen(t, blob, k2, nil, want)

	pw, err := os.ReadFile("testdata/v1-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}
	blob, err = rewrapEdit(t, pw, nil, []byte("golden"), SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Argon: testArgon},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustOpen(t, blob, nil, []byte("golden"), want)
}

func TestRewrapEditKeepsUnknownSlots(t *testing.T) {
	k := newIdentity(t)
	plain := randomBytes(t, 100)
	// A foreign writer's file can carry a slot type this version does not
	// know; keep must carry it verbatim rather than dropping it silently.
	fileKey := randomBytes(t, fileKeySize)
	fileNonce := randomBytes(t, fileNonceSize)
	var buf bytes.Buffer
	err := writeHeaderV2(&buf, fileKey, fileNonce,
		[]parsedSlot{{slotType: 0x7f, body: randomBytes(t, 40)}},
		SealOptions{Recipients: [][]byte{k.PublicKey()}})
	if err != nil {
		t.Fatal(err)
	}
	payloadKey, err := hkdf.Key(sha256.New, fileKey, fileNonce, payloadInfo, chacha20poly1305.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealPayload(&buf, bytes.NewReader(plain), payloadKey); err != nil {
		t.Fatal(err)
	}
	old := buf.Bytes()

	blob, err := rewrapEdit(t, old, k, nil, SlotEdit{
		KeepAll: true,
		Add:     SealOptions{Recipients: [][]byte{newIdentity(t).PublicKey()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slotRecord(t, old, 1), slotRecord(t, blob, 1)) {
		t.Fatal("unknown slot not carried verbatim")
	}
	mustOpen(t, blob, k, nil, plain)
}

func TestSlotStripping(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	blob := sealTo(t, randomBytes(t, 100), SealOptions{
		Recipients: [][]byte{k1.PublicKey(), k2.PublicKey()},
	})
	// Rebuild the file with the second slot removed and the count patched.
	slotLen := 3 + xwingSlotBody
	stripped := append([]byte(nil), blob[:25+slotLen]...)
	stripped[24] = 1
	stripped = append(stripped, blob[25+2*slotLen:]...)

	if _, err := openWith(t, stripped, k1, nil); !errors.Is(err, ErrHeaderTampered) {
		t.Fatalf("got %v, want ErrHeaderTampered", err)
	}
}

func TestWrongIdentity(t *testing.T) {
	k1, k2 := newIdentity(t), newIdentity(t)
	blob := sealTo(t, []byte("secret"), SealOptions{Recipients: [][]byte{k1.PublicKey()}})
	if _, err := openWith(t, blob, k2, nil); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	blob := sealTo(t, []byte("secret"), SealOptions{Passphrases: [][]byte{[]byte("right")}, Argon: testArgon})
	if _, err := openWith(t, blob, nil, []byte("wrong")); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestModeErrors(t *testing.T) {
	k := newIdentity(t)
	rec := sealTo(t, []byte("x"), SealOptions{Recipients: [][]byte{k.PublicKey()}})
	pw := sealTo(t, []byte("x"), SealOptions{Passphrases: [][]byte{[]byte("p")}, Argon: testArgon})

	if _, err := openWith(t, rec, nil, []byte("p")); !errors.Is(err, ErrNeedIdentity) {
		t.Fatalf("got %v, want ErrNeedIdentity", err)
	}
	if _, err := openWith(t, pw, k, nil); !errors.Is(err, ErrNeedPassphrase) {
		t.Fatalf("got %v, want ErrNeedPassphrase", err)
	}
}

func TestNotSindook(t *testing.T) {
	for _, junk := range [][]byte{nil, []byte("short"), randomBytes(t, 200)} {
		if _, err := openWith(t, junk, nil, []byte("p")); !errors.Is(err, ErrNotSindook) {
			t.Fatalf("got %v, want ErrNotSindook", err)
		}
	}
}

// TestTamper flips one byte in every region of a single-passphrase v2 file
// (nonce, slot count, slot type, KDF params, salt, wrapped key, header MAC,
// payload) and requires each variant to fail. Offsets follow docs/FORMAT.md.
func TestTamper(t *testing.T) {
	pass := []byte("p")
	blob := sealTo(t, randomBytes(t, 300), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})

	for _, pos := range []int{8, 24, 25, 30, 60, 90, v2PassHeader - 5, v2PassHeader + 5, len(blob) - 1} {
		tampered := append([]byte(nil), blob...)
		tampered[pos] ^= 0x01
		if _, err := openWith(t, tampered, nil, pass); err == nil {
			t.Fatalf("tampering byte %d went undetected", pos)
		}
	}

	macFlip := append([]byte(nil), blob...)
	macFlip[v2PassHeader-macSize+3] ^= 0x01
	if _, err := openWith(t, macFlip, nil, pass); !errors.Is(err, ErrHeaderTampered) {
		t.Fatalf("MAC flip: got %v, want ErrHeaderTampered", err)
	}
}

func TestTruncation(t *testing.T) {
	pass := []byte("p")
	blob := sealTo(t, randomBytes(t, 2*chunkSize+513), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon})
	const payloadStart = v2PassHeader
	overhead := chacha20poly1305.Overhead

	cuts := []int{
		payloadStart,                              // payload removed entirely
		payloadStart + chunkSize + overhead,       // cut at first chunk boundary
		payloadStart + 2*(chunkSize+overhead) - 7, // cut inside second chunk
		len(blob) - 1,                             // final tag shortened
	}
	for _, cut := range cuts {
		if _, err := openWith(t, blob[:cut], nil, pass); !errors.Is(err, ErrPayloadCorrupted) {
			t.Fatalf("cut at %d: got %v, want ErrPayloadCorrupted", cut, err)
		}
	}
	extended := append(append([]byte(nil), blob...), 0x00)
	if _, err := openWith(t, extended, nil, pass); !errors.Is(err, ErrPayloadCorrupted) {
		t.Fatalf("extension: got %v, want ErrPayloadCorrupted", err)
	}
}

func TestArgonParamCaps(t *testing.T) {
	bad := []Argon2idParams{
		{Time: 0, MemoryKiB: 64, Threads: 1},
		{Time: 65, MemoryKiB: 64, Threads: 1},
		{Time: 1, MemoryKiB: 4, Threads: 1},
		{Time: 1, MemoryKiB: 2 * 1024 * 1024, Threads: 1},
		{Time: 1, MemoryKiB: 64, Threads: 0},
	}
	for i, p := range bad {
		var sealed bytes.Buffer
		if err := SealPassphrase(&sealed, bytes.NewReader(nil), []byte("p"), p); err == nil {
			t.Fatalf("case %d: invalid params accepted", i)
		}
	}
}

func TestSlotLimits(t *testing.T) {
	k := newIdentity(t)
	tooMany := make([][]byte, maxSlots+1)
	for i := range tooMany {
		tooMany[i] = k.PublicKey()
	}
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(nil), SealOptions{Recipients: tooMany}); err == nil {
		t.Fatal("slot cap not enforced")
	}
	if err := Seal(&sealed, bytes.NewReader(nil), SealOptions{}); err == nil {
		t.Fatal("empty options accepted")
	}
	if err := Seal(io.Discard, bytes.NewReader(nil), SealOptions{
		Passphrases: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
		Argon:       testArgon,
	}); err == nil {
		t.Fatal("passphrase slot cap not enforced")
	}
}

// TestSealAfterLockAll verifies that calling memguard.LockAll does not break
// subsequent passphrase sealing. This guards the MCL_FUTURE OOM regression
// where a low RLIMIT_MEMLOCK caused the next 64 MiB argon2 allocation to
// be locked and abort the runtime.
func TestSealAfterLockAll(t *testing.T) {
	if err := memguard.LockAll(); err != nil {
		t.Logf("memguard.LockAll: %v", err)
	}
	t.Logf("memguard status: %s", memguard.Status())

	// Prepare keys outside the timeout goroutine so we don't call testing.T
	// helpers from another goroutine.
	k := newIdentity(t)
	plain := []byte("after LockAll payload")
	pass := []byte("test-pass")

	done := make(chan error, 1)
	go func() {
		// Passphrase-only round-trip.
		var sealed bytes.Buffer
		if err := Seal(&sealed, bytes.NewReader(plain), SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon}); err != nil {
			done <- err
			return
		}
		blob := sealed.Bytes()
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(blob), nil, pass); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(out.Bytes(), plain) {
			done <- errors.New("passphrase round-trip mismatch after LockAll")
			return
		}
		// Mixed slots.
		sealed.Reset()
		if err := Seal(&sealed, bytes.NewReader(plain), SealOptions{Recipients: [][]byte{k.PublicKey()}, Passphrases: [][]byte{pass}, Argon: testArgon}); err != nil {
			done <- err
			return
		}
		blob = sealed.Bytes()
		out.Reset()
		if err := Open(&out, bytes.NewReader(blob), k, nil); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(out.Bytes(), plain) {
			done <- errors.New("mixed recipient round-trip mismatch after LockAll")
			return
		}
		out.Reset()
		if err := Open(&out, bytes.NewReader(blob), nil, pass); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(out.Bytes(), plain) {
			done <- errors.New("mixed passphrase round-trip mismatch after LockAll")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("seal after LockAll failed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("seal after LockAll timed out (possible memguard deadlock/OOM)")
	}
}
