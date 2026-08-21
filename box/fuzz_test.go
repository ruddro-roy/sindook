package box

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/xwing"
)

// The fuzz targets attack the two hand-written binary parsers (unlockV2,
// unlockV1) and the chunked payload state machine with hostile bytes. The
// invariants are absolute: no panic, no unbounded work, successful opens are
// deterministic, and no modified byte of a valid file ever opens cleanly.
// Crash regressions land in testdata/fuzz and replay under plain go test.

// fuzzArgon mirrors testArgon in box_test.go; duplicated here so this file
// stays self-contained for the ClusterFuzzLite libFuzzer build, which
// compiles it without the rest of the test package.
var fuzzArgon = Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}

// fuzzIdentity is the fixed identity of the v1 golden fixtures, so fixture
// seeds reach past credential checks into MAC and payload verification.
// It panics instead of taking a testing.TB so the libFuzzer shim, whose
// testing package lacks TB, can compile this file.
func fuzzIdentity() *xwing.PrivateKey {
	seed, err := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	if err != nil {
		panic(err)
	}
	id, err := xwing.NewPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	return id
}

func fuzzSecondIdentity() *xwing.PrivateKey {
	seed, err := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		panic(err)
	}
	id, err := xwing.NewPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	return id
}

func addFixtureSeeds(f *testing.F) {
	for _, name := range []string{"testdata/v1-recipient.sindook", "testdata/v1-passphrase.sindook"} {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
}

// reopen requires that a blob which opened once opens again with identical
// output, catching any state leaking between parses. Panic-based rather
// than testing.T-based for the same shim-compatibility reason as above.
func reopen(data, want []byte, id *xwing.PrivateKey, pass []byte) {
	var again bytes.Buffer
	if err := Open(&again, bytes.NewReader(data), id, pass); err != nil {
		panic("second open of accepted input failed: " + err.Error())
	}
	if !bytes.Equal(again.Bytes(), want) {
		panic("open is not deterministic")
	}
}

func FuzzOpenRecipient(f *testing.F) {
	id := fuzzIdentity()
	addFixtureSeeds(f)
	var v2 bytes.Buffer
	if err := Seal(&v2, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Recipients: [][]byte{id.PublicKey()}}); err != nil {
		f.Fatal(err)
	}
	f.Add(v2.Bytes())
	f.Add([]byte(magicV1))
	f.Add([]byte(magicV2))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(data), id, nil); err != nil {
			return
		}
		reopen(data, out.Bytes(), id, nil)
	})
}

// maxFuzzArgonWork caps declared Time*MemoryKiB per passphrase slot. The
// parser's own ceiling (maxArgonTime, maxArgonMemoryKiB) is deliberately
// generous so files sealed with strong parameters stay openable, but a
// hostile header near that ceiling costs seconds of KDF work before
// rejection, which would stall the fuzzer. Default parameters fit under
// this budget, so both golden fixtures still fuzz the full path.
const maxFuzzArgonWork = 4 * 64 * 1024

// argonWorkBounded reads just enough of a candidate header to find declared
// Argon2id parameters. Truncated or malformed inputs return true: the real
// parser rejects those before any KDF runs.
func argonWorkBounded(data []byte) bool {
	if len(data) < len(magicV2)+1 {
		return true
	}
	switch string(data[:len(magicV2)]) {
	case magicV1:
		if data[8] != modeV1Passphrase || len(data) < 17 {
			return true
		}
		work := uint64(binary.BigEndian.Uint32(data[9:13])) * uint64(binary.BigEndian.Uint32(data[13:17]))
		return work <= maxFuzzArgonWork
	case magicV2:
		if len(data) < 25 {
			return true
		}
		count := int(data[24])
		if count > maxSlots {
			return true
		}
		off := 25
		for i := 0; i < count; i++ {
			if off+3 > len(data) {
				return true
			}
			bodyLen := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
			body := data[off+3:]
			if bodyLen > len(body) {
				return true
			}
			if data[off] == SlotPassphrase && bodyLen >= 8 {
				work := uint64(binary.BigEndian.Uint32(body[0:4])) * uint64(binary.BigEndian.Uint32(body[4:8]))
				if work > maxFuzzArgonWork {
					return false
				}
			}
			off += 3 + bodyLen
		}
	}
	return true
}

func FuzzOpenPassphrase(f *testing.F) {
	pass := []byte("golden")
	addFixtureSeeds(f)
	var v2 bytes.Buffer
	if err := Seal(&v2, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Passphrases: [][]byte{pass}, Argon: fuzzArgon}); err != nil {
		f.Fatal(err)
	}
	f.Add(v2.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		if !argonWorkBounded(data) {
			t.Skip("declared KDF work above fuzz budget")
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(data), nil, pass); err != nil {
			return
		}
		reopen(data, out.Bytes(), nil, pass)
	})
}

func FuzzSealOpenRoundTrip(f *testing.F) {
	id := fuzzIdentity()
	pass := []byte("fuzz")
	f.Add([]byte(nil), false)
	f.Add(bytes.Repeat([]byte{0xA5}, chunkSize+1), true)

	f.Fuzz(func(t *testing.T, plain []byte, usePass bool) {
		opts := SealOptions{Recipients: [][]byte{id.PublicKey()}}
		openID, openPass := id, []byte(nil)
		if usePass {
			opts = SealOptions{Passphrases: [][]byte{pass}, Argon: fuzzArgon}
			openID, openPass = nil, pass
		}
		var sealed bytes.Buffer
		if err := Seal(&sealed, bytes.NewReader(plain), opts); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(sealed.Bytes()), openID, openPass); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatal("round trip mismatch")
		}
	})
}

// FuzzBitFlip generalizes TestTamper from nine chosen offsets to every
// position and value the fuzzer reaches: XORing any byte of a valid sealed
// file must never open cleanly, and appending trailing bytes must fail.
func FuzzBitFlip(f *testing.F) {
	id := fuzzIdentity()
	plain := []byte("bit flip corpus payload, long enough to cross into the payload region")
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(plain), SealOptions{Recipients: [][]byte{id.PublicKey()}}); err != nil {
		f.Fatal(err)
	}
	blob := sealed.Bytes()
	f.Add(uint32(8), byte(0x01))
	f.Add(uint32(len(blob)-1), byte(0x80))

	f.Fuzz(func(t *testing.T, pos uint32, xor byte) {
		if xor == 0 {
			t.Skip("identity mutation")
		}
		mutated := append([]byte(nil), blob...)
		if int(pos) >= len(mutated) {
			mutated = append(mutated, xor)
		} else {
			mutated[pos] ^= xor
		}
		if err := Open(io.Discard, bytes.NewReader(mutated), id, nil); err == nil {
			t.Fatalf("mutation pos=%d xor=%#02x opened cleanly", pos, xor)
		}
	})
}

// FuzzOpen exercises the full Open path with both credential kinds and
// armor-wrapped inputs. It is the unified entry point for `go test
// -fuzz=FuzzOpen` and must stay fast: KDF work is bounded and payloads
// are limited to 1 MiB after armor decoding.
func FuzzOpen(f *testing.F) {
	id := fuzzIdentity()
	pass := []byte("golden")
	addFixtureSeeds(f)
	var v2Rec, v2Pass bytes.Buffer
	if err := Seal(&v2Rec, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Recipients: [][]byte{id.PublicKey()}}); err == nil {
		f.Add(v2Rec.Bytes())
		var armored bytes.Buffer
		w := armor.NewWriter(&armored)
		_, _ = w.Write(v2Rec.Bytes())
		_ = w.Close()
		f.Add(armored.Bytes())
	}
	if err := Seal(&v2Pass, bytes.NewReader([]byte("fuzz seed payload")), SealOptions{Passphrases: [][]byte{pass}, Argon: fuzzArgon}); err == nil {
		f.Add(v2Pass.Bytes())
	}
	// Mixed slot file: both recipient and passphrase in one header.
	var mixed bytes.Buffer
	if err := Seal(&mixed, bytes.NewReader([]byte("mixed seed")), SealOptions{Recipients: [][]byte{id.PublicKey()}, Passphrases: [][]byte{pass}, Argon: fuzzArgon}); err == nil {
		f.Add(mixed.Bytes())
	}
	f.Add([]byte(magicV1))
	f.Add([]byte(magicV2))

	f.Fuzz(func(t *testing.T, data []byte) {
		if !argonWorkBounded(data) {
			t.Skip("declared KDF work above fuzz budget")
		}
		testBlob := func(blob []byte) {
			// Recipient path.
			var out bytes.Buffer
			if err := Open(&out, bytes.NewReader(blob), id, nil); err == nil {
				reopen(blob, out.Bytes(), id, nil)
				// Header tampering check: flipping any byte of a valid file must not open cleanly.
				// We already test via FuzzBitFlip, but also ensure Inspect is deterministic on accepted blobs.
				info, err := Inspect(bytes.NewReader(blob))
				if err != nil {
					t.Fatalf("valid blob fails Inspect: %v", err)
				}
				if info.HeaderSize <= 0 || info.HeaderSize > int64(len(blob)) {
					t.Fatalf("implausible header size %d for blob len %d", info.HeaderSize, len(blob))
				}
			}
			// Passphrase path.
			var out2 bytes.Buffer
			if err := Open(&out2, bytes.NewReader(blob), nil, pass); err == nil {
				reopen(blob, out2.Bytes(), nil, pass)
			}
			// Mixed credentials available: should still be deterministic.
			var out3 bytes.Buffer
			if err := Open(&out3, bytes.NewReader(blob), id, pass); err == nil {
				reopen(blob, out3.Bytes(), id, pass)
			}
			// Inspect must never panic and must be deterministic even on hostile input.
			info1, err1 := Inspect(bytes.NewReader(blob))
			info2, err2 := Inspect(bytes.NewReader(blob))
			if (err1 == nil) != (err2 == nil) {
				t.Fatal("Inspect not deterministic")
			}
			if err1 == nil {
				if info1.Version != info2.Version || len(info1.Slots) != len(info2.Slots) || info1.HeaderSize != info2.HeaderSize {
					t.Fatal("Inspect not deterministic")
				}
				if info1.HeaderSize < 0 || info1.HeaderSize > int64(len(blob)) {
					t.Fatalf("Inspect header size out of range: %d", info1.HeaderSize)
				}
				// PlaintextSize must be consistent: if Inspect succeeds and blob is longer than header,
				// payload length is len(blob)-headerSize; PlaintextSize must not panic.
				payloadLen := int64(len(blob)) - info1.HeaderSize
				_ = PlaintextSize(payloadLen)
			}
		}
		testBlob(data)
		// If input looks armored, also test the armor-decoded inner blob.
		if armor.IsArmored(data) {
			dec, err := io.ReadAll(io.LimitReader(armor.NewReader(bytes.NewReader(data)), 1<<20))
			if err != nil {
				return
			}
			if !argonWorkBounded(dec) {
				t.Skip("decoded inner declares excessive KDF work")
			}
			testBlob(dec)
			// Accepted armor must survive canonical re-encode.
			var re bytes.Buffer
			aw := armor.NewWriter(&re)
			_, _ = aw.Write(dec)
			if err := aw.Close(); err != nil {
				t.Fatalf("armor re-encode failed: %v", err)
			}
			again, err := io.ReadAll(armor.NewReader(bytes.NewReader(re.Bytes())))
			if err != nil || !bytes.Equal(again, dec) {
				t.Fatalf("armor canonical re-encode broken: %v", err)
			}
		}
	})
}

// FuzzRewrap exercises Rewrap with arbitrary hostile bytes and with both
// credential kinds, in both fast and deep modes. The invariants mirror
// Open: no panic, no unbounded KDF, and any successful rewrap must produce
// a file that opens with the new credentials to the same plaintext, with
// header-MAC integrity on the result.
func FuzzRewrap(f *testing.F) {
	id1 := fuzzIdentity()
	id2 := fuzzSecondIdentity()
	passOld := []byte("golden")
	passNew := []byte("newpass")
	for _, name := range []string{"testdata/v1-recipient.sindook", "testdata/v1-passphrase.sindook"} {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b, false)
			f.Add(b, true)
		}
	}
	// Valid blobs for seeds: recipient, passphrase, and mixed.
	for _, opts := range []SealOptions{
		{Recipients: [][]byte{id1.PublicKey()}},
		{Passphrases: [][]byte{passOld}, Argon: fuzzArgon},
		{Recipients: [][]byte{id1.PublicKey()}, Passphrases: [][]byte{passOld}, Argon: fuzzArgon},
	} {
		var buf bytes.Buffer
		if err := Seal(&buf, bytes.NewReader([]byte("rewrap seed payload")), opts); err == nil {
			f.Add(buf.Bytes(), false)
			f.Add(buf.Bytes(), true)
		}
	}
	// Tampered seed: one byte flipped in header (should still be exercised as hostile input).
	var tmp bytes.Buffer
	_ = Seal(&tmp, bytes.NewReader([]byte("seed")), SealOptions{Recipients: [][]byte{id1.PublicKey()}})
	if b := tmp.Bytes(); len(b) > 30 {
		mut := append([]byte(nil), b...)
		mut[30] ^= 0x01
		f.Add(mut, false)
	}

	f.Fuzz(func(t *testing.T, data []byte, deep bool) {
		if !argonWorkBounded(data) {
			t.Skip("declared KDF work above fuzz budget")
		}
		// Limit decoded armor to 1 MiB to keep the fuzzer fast; if data is armored
		// we test the inner bytes as the hostile header (Rewrap expects raw).
		blob := data
		if armor.IsArmored(data) {
			dec, err := io.ReadAll(io.LimitReader(armor.NewReader(bytes.NewReader(data)), 1<<20))
			if err != nil {
				// Malformed armor: Rewrap should reject cleanly, no panic.
				var out bytes.Buffer
				_ = Rewrap(&out, bytes.NewReader(data), id1, nil, SealOptions{Recipients: [][]byte{id2.PublicKey()}}, deep)
				return
			}
			if !argonWorkBounded(dec) {
				t.Skip("decoded inner excessive KDF")
			}
			blob = dec
		}
		// Try rewrapping with each source credential kind, and each destination kind.
		type src struct {
			id   *xwing.PrivateKey
			pass []byte
		}
		srcs := []src{{id: id1}, {pass: passOld}}
		dsts := []SealOptions{
			{Recipients: [][]byte{id2.PublicKey()}},
			{Passphrases: [][]byte{passNew}, Argon: fuzzArgon},
		}
		for _, s := range srcs {
			for _, dst := range dsts {
				var out bytes.Buffer
				err := Rewrap(&out, bytes.NewReader(blob), s.id, s.pass, dst, deep)
				if err != nil {
					continue
				}
				// Rewrap succeeded: original must have been a valid file openable with src.
				var expect bytes.Buffer
				if err := Open(&expect, bytes.NewReader(blob), s.id, s.pass); err != nil {
					t.Fatalf("rewrap succeeded on input that doesn't open with source credentials")
				}
				// New file must open with destination credentials and match plaintext.
				var dstID *xwing.PrivateKey
				var dstPass []byte
				if len(dst.Recipients) > 0 {
					dstID = id2
				} else {
					dstPass = passNew
				}
				var got bytes.Buffer
				if err := Open(&got, bytes.NewReader(out.Bytes()), dstID, dstPass); err != nil {
					t.Fatalf("rewrapped file doesn't open with destination credentials: %v", err)
				}
				if !bytes.Equal(got.Bytes(), expect.Bytes()) {
					t.Fatalf("rewrapped plaintext mismatch")
				}
				// Header MAC on rewrapped file must be checked: tampering one byte must fail.
				rewrapped := out.Bytes()
				if len(rewrapped) > 30 {
					mut := append([]byte(nil), rewrapped...)
					mut[30] ^= 0x01
					if err := Open(io.Discard, bytes.NewReader(mut), dstID, dstPass); err == nil {
						t.Fatalf("tampered rewrapped file opened cleanly")
					}
				}
				// Payload preservation: fast mode must keep payload bytes verbatim.
				infoOld, errOld := Inspect(bytes.NewReader(blob))
				infoNew, errNew := Inspect(bytes.NewReader(rewrapped))
				if errOld == nil && errNew == nil {
					oldPayload := blob[infoOld.HeaderSize:]
					newPayload := rewrapped[infoNew.HeaderSize:]
					if !deep {
						if !bytes.Equal(oldPayload, newPayload) {
							t.Fatal("fast rewrap modified payload bytes")
						}
					} else if len(expect.Bytes()) > 0 && bytes.Equal(oldPayload, newPayload) {
						t.Fatal("deep rewrap left payload bytes unchanged")
					}
				}
			}
		}
	})
}

// FuzzRewrapRoundTrip is a generative counterpart to FuzzRewrap: it seals
// fresh plaintext, rewraps through every credential combination and both
// fast/deep modes, then opens the result. This covers the Rewrap header
// reconstruction with well-formed inputs, while FuzzRewrap covers hostile
// headers.
func FuzzRewrapRoundTrip(f *testing.F) {
	id1 := fuzzIdentity()
	id2 := fuzzSecondIdentity()
	passOld := []byte("oldpass")
	passNew := []byte("newpass")
	f.Add([]byte(nil), false, false, false)
	f.Add([]byte("hello world"), true, false, true)
	f.Add(bytes.Repeat([]byte{0xA5}, chunkSize+1), false, true, true)
	f.Add(bytes.Repeat([]byte("x"), 2*chunkSize+100), true, true, false)

	f.Fuzz(func(t *testing.T, plain []byte, sealWithPass bool, rewrapWithPass bool, deep bool) {
		sealOpts := SealOptions{Recipients: [][]byte{id1.PublicKey()}}
		sealID, sealPass := id1, []byte(nil)
		if sealWithPass {
			sealOpts = SealOptions{Passphrases: [][]byte{passOld}, Argon: fuzzArgon}
			sealID, sealPass = nil, passOld
		}
		var sealed bytes.Buffer
		if err := Seal(&sealed, bytes.NewReader(plain), sealOpts); err != nil {
			t.Fatal(err)
		}
		// Verify sealed file opens before rewrap (sanity).
		var chk bytes.Buffer
		if err := Open(&chk, bytes.NewReader(sealed.Bytes()), sealID, sealPass); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(chk.Bytes(), plain) {
			t.Fatal("pre-rewrap round trip mismatch")
		}

		rewrapOpts := SealOptions{Recipients: [][]byte{id2.PublicKey()}}
		newID, newPass := id2, []byte(nil)
		if rewrapWithPass {
			rewrapOpts = SealOptions{Passphrases: [][]byte{passNew}, Argon: fuzzArgon}
			newID, newPass = nil, passNew
		}
		var rewrapped bytes.Buffer
		if err := Rewrap(&rewrapped, bytes.NewReader(sealed.Bytes()), sealID, sealPass, rewrapOpts, deep); err != nil {
			t.Fatalf("rewrap failed: %v", err)
		}
		var out bytes.Buffer
		if err := Open(&out, bytes.NewReader(rewrapped.Bytes()), newID, newPass); err != nil {
			t.Fatalf("open after rewrap failed: %v", err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatal("rewrap round trip plaintext mismatch")
		}
		// Old credentials must not open after deep rewrap if they differ from new.
		// For fast rewrap with same plaintext but different recipient set, old recipient
		// may still be present only if dst includes them; since here dst is distinct
		// (id2 vs id1, or newpass vs oldpass), deep must revoke old.
		if deep {
			// Try old creds; they should fail because dst is different entity.
			// For the passphrase->passphrase case, old pass should not open new file sealed to newpass.
			// For mixed we already know dst differs, so expect ErrWrongKey or similar.
			if err := Open(io.Discard, bytes.NewReader(rewrapped.Bytes()), sealID, sealPass); err == nil {
				// Only acceptable if seal and rewrap used same credential value (they don't in this test).
				t.Fatalf("deep rewrap did not revoke old credentials")
			}
		}
	})
}

// FuzzInspect exercises the header-only parser (Inspect) on arbitrary bytes.
// Inspect applies the same structural caps as unlocking but cannot verify the
// header MAC, so the invariants are: no panic, deterministic, and well-formed
// headers expose sane metadata.
func FuzzInspect(f *testing.F) {
	id := fuzzIdentity()
	addFixtureSeeds(f)
	for _, opts := range []SealOptions{
		{Recipients: [][]byte{id.PublicKey()}},
		{Passphrases: [][]byte{[]byte("inspect")}, Argon: fuzzArgon},
		{Recipients: [][]byte{id.PublicKey(), fuzzSecondIdentity().PublicKey()}},
	} {
		var buf bytes.Buffer
		if err := Seal(&buf, bytes.NewReader([]byte("inspect payload")), opts); err == nil {
			f.Add(buf.Bytes())
		}
	}
	f.Add([]byte(magicV1))
	f.Add([]byte(magicV2))
	f.Add([]byte("not a sindook file"))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		info1, err1 := Inspect(bytes.NewReader(data))
		info2, err2 := Inspect(bytes.NewReader(data))
		// Determinism.
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("Inspect not deterministic")
		}
		if err1 != nil {
			return
		}
		if info1.Version != info2.Version || info1.HeaderSize != info2.HeaderSize || len(info1.Slots) != len(info2.Slots) {
			t.Fatal("Inspect second call differs")
		}
		if info1.Version != 1 && info1.Version != 2 {
			t.Fatalf("unexpected version %d", info1.Version)
		}
		if len(info1.Slots) == 0 || len(info1.Slots) > maxSlots {
			t.Fatalf("slot count %d out of range", len(info1.Slots))
		}
		if info1.HeaderSize <= 0 || info1.HeaderSize > int64(len(data)) {
			t.Fatalf("header size %d out of range for input len %d", info1.HeaderSize, len(data))
		}
		for _, s := range info1.Slots {
			if s.Body < 0 || s.Body > maxSlotBody {
				t.Fatalf("slot body %d out of range", s.Body)
			}
			if s.Type == SlotPassphrase && s.Argon != nil {
				if err := s.Argon.validate(); err != nil {
					t.Fatalf("Inspect exposed invalid argon params: %v", err)
				}
			}
		}
		payloadLen := int64(len(data)) - info1.HeaderSize
		ps := PlaintextSize(payloadLen)
		// PlaintextSize must not panic and must be -1 or >=0 and <= payloadLen.
		if ps < -1 || ps > payloadLen {
			t.Fatalf("PlaintextSize(%d)=%d out of range", payloadLen, ps)
		}
		// If the data is actually a valid sealed file (Open succeeds with one of our creds),
		// then PlaintextSize should match the true plaintext length and header sizes must line up.
		for _, cred := range []struct {
			id   *xwing.PrivateKey
			pass []byte
		}{{id: id}, {pass: []byte("inspect")}, {id: id, pass: []byte("inspect")}} {
			var out bytes.Buffer
			if err := Open(&out, bytes.NewReader(data), cred.id, cred.pass); err == nil {
				if ps != int64(len(out.Bytes())) {
					t.Fatalf("PlaintextSize %d != actual plaintext %d", ps, len(out.Bytes()))
				}
				// Re-Inspect must give same header size.
				infoAgain, err := Inspect(bytes.NewReader(data))
				if err != nil || infoAgain.HeaderSize != info1.HeaderSize {
					t.Fatalf("Inspect header size not stable for valid file")
				}
				break
			}
		}
		// Mutating one byte of the inspected header should not panic on re-inspect,
		// and if it still parses, the new header size must remain plausible.
		if len(data) > 10 {
			mut := append([]byte(nil), data...)
			mut[10] ^= 0x01
			infoMut, err := Inspect(bytes.NewReader(mut))
			if err == nil {
				if infoMut.HeaderSize <= 0 || infoMut.HeaderSize > int64(len(mut)) {
					t.Fatalf("mutated header size %d implausible", infoMut.HeaderSize)
				}
			}
		}
	})
}
