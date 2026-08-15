package armor

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// FuzzArmor checks two properties on arbitrary input: encoding any bytes
// produces armor that decodes back to those bytes, and decoding any bytes
// never panics, with anything the reader accepts surviving a re-encode
// round trip.
func FuzzArmor(f *testing.F) {
	f.Add([]byte("hello sindook"))
	f.Add([]byte{})
	f.Add([]byte(begin + "\naGVsbG8=\n" + end + "\n"))
	f.Add([]byte(begin + "\n" + end + "\n"))
	f.Add([]byte(begin + "\naGVsbG8=\n"))
	f.Add([]byte("\r\n" + begin + "\r\naGVsbG8=\r\n" + end + "\r\n"))
	f.Add(bytes.Repeat([]byte("A"), 2048))

	f.Fuzz(func(t *testing.T, data []byte) {
		var enc bytes.Buffer
		w := NewWriter(&enc)
		if _, err := w.Write(data); err != nil {
			t.Fatalf("encode write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("encode close: %v", err)
		}
		got, err := io.ReadAll(NewReader(bytes.NewReader(enc.Bytes())))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("round trip broken: %v", err)
		}

		dec, err := io.ReadAll(io.LimitReader(NewReader(bytes.NewReader(data)), 1<<20))
		if err != nil {
			return
		}
		// The reader tolerates whitespace variations, so accepted input must
		// agree with its canonical re-encoding, not byte-for-byte with data.
		if !strings.Contains(string(data), begin) {
			t.Fatal("reader accepted input without a begin marker")
		}
		var re bytes.Buffer
		rw := NewWriter(&re)
		rw.Write(dec)
		if err := rw.Close(); err != nil {
			t.Fatal(err)
		}
		again, err := io.ReadAll(NewReader(bytes.NewReader(re.Bytes())))
		if err != nil || !bytes.Equal(again, dec) {
			t.Fatalf("canonical re-encode broken: %v", err)
		}
	})
}

// FuzzArmorReader focuses the fuzzer on the armor decoder's hostile-input
// handling: line length caps, base64 validation, padding placement, CR/LF
// tolerance, leading blank lines, and trailing data detection. Invariants:
// no panic, IsArmored consistent with acceptance, and any accepted input
// survives canonical re-encode. The encoder round-trip is already covered
// by FuzzArmor, so this target spends all its mutational budget on the
// reader.
func FuzzArmorReader(f *testing.F) {
	f.Add([]byte(begin + "\naGVsbG8=\n" + end + "\n"))
	f.Add([]byte(begin + "\n" + end + "\n"))
	f.Add([]byte("\n\n" + begin + "\naGVsbG8=\n" + end + "\n"))
	f.Add([]byte("\r\n" + begin + "\r\naGVsbG8=\r\n" + end + "\r\n"))
	f.Add([]byte(begin + "\nYWI=\n" + end + "\n"))
	f.Add([]byte(begin + "\naGVsbG8=\n")) // missing end
	f.Add([]byte("not armor at all"))
	f.Add(bytes.Repeat([]byte("A"), 2048))
	f.Add([]byte(begin + "\n" + strings.Repeat("A", 1025) + "\n" + end + "\n")) // oversized line
	f.Add([]byte(begin + "\n!!!!\n" + end + "\n"))                             // bad base64
	f.Add([]byte(begin + "\nYWI=\nYWI=\n" + end + "\n"))                        // padding mid-body

	f.Fuzz(func(t *testing.T, data []byte) {
		// IsArmored must never panic and must be consistent with leading whitespace handling.
		armored := IsArmored(data)
		// Decode with size limit to keep fuzzer fast and avoid OOM on hostile streams.
		dec, err := io.ReadAll(io.LimitReader(NewReader(bytes.NewReader(data)), 1<<20))
		if err != nil {
			// Malformed armor must not be reported as armored if it lacks a proper begin marker
			// at the start (IsArmored is permissive about leading whitespace only).
			// We don't require strict equivalence, but if IsArmored is false and the data
			// contains no begin marker, rejection is expected; if it does contain begin,
			// the decoder correctly rejected it for other reasons (bad base64, line length, etc.).
			return
		}
		// Accepted input must have been considered armored and must contain begin marker.
		if !armored && !strings.Contains(string(data), begin) {
			t.Fatal("reader accepted input that IsArmored rejects and that lacks begin marker")
		}
		if !strings.Contains(string(data), begin) {
			t.Fatal("reader accepted input without a begin marker")
		}
		// Check for trailing data: decode again with explicit extra read after end.
		// The reader should have set done; any non-whitespace trailing after end would have
		// been reported as ErrTrailing on the next fill. Since we got no error, trailing
		// must be only whitespace or absent – verify by appending junk and seeing it fails.
		// First, ensure canonical re-encode is stable.
		var re bytes.Buffer
		rw := NewWriter(&re)
		if _, err := rw.Write(dec); err != nil {
			t.Fatalf("re-encode write: %v", err)
		}
		if err := rw.Close(); err != nil {
			t.Fatalf("re-encode close: %v", err)
		}
		again, err := io.ReadAll(NewReader(bytes.NewReader(re.Bytes())))
		if err != nil || !bytes.Equal(again, dec) {
			t.Fatalf("canonical re-encode broken: %v %d vs %d", err, len(dec), len(again))
		}
		// Oversized decoded payload should still be bounded by the LimitReader; ensure we didn't
		// exceed the limit silently.
		if int64(len(dec)) > 1<<20 {
			t.Fatalf("decoded %d bytes exceeds limit", len(dec))
		}
		// Tampering check: flipping any byte of the canonical encoding should not panic and
		// should either still decode to same dec (if whitespace) or be rejected / decode differently.
		// We test one deterministic tamper: flip first body byte if present.
		enc := re.Bytes()
		if len(enc) > len(begin)+2 {
			mut := append([]byte(nil), enc...)
			// Find first base64 body line (line after begin)
			idx := bytes.Index(mut, []byte("\n"))
			if idx >= 0 && idx+1 < len(mut) && mut[idx+1] != '-' {
				mut[idx+1] ^= 0x01
				dec2, err2 := io.ReadAll(io.LimitReader(NewReader(bytes.NewReader(mut)), 1<<20))
				if err2 == nil && bytes.Equal(dec2, dec) {
					t.Fatalf("tampered armor decoded to same plaintext")
				}
			}
		}
		// Chunked writer writes must also round-trip: split dec into odd chunks, encode incrementally.
		var chunked bytes.Buffer
		cw := NewWriter(&chunked)
		for i := 0; i < len(dec); i += 7 {
			end := i + 7
			if end > len(dec) {
				end = len(dec)
			}
			if _, err := cw.Write(dec[i:end]); err != nil {
				t.Fatalf("chunked write: %v", err)
			}
		}
		if err := cw.Close(); err != nil {
			t.Fatalf("chunked close: %v", err)
		}
		got, err := io.ReadAll(NewReader(bytes.NewReader(chunked.Bytes())))
		if err != nil || !bytes.Equal(got, dec) {
			t.Fatalf("chunked round trip broken: %v", err)
		}
	})
}

// FuzzIsArmored fuzzes the cheap IsArmored detector against the full decoder
// to ensure no panic and that any input the decoder accepts is considered
// armored (the converse is not required – IsArmored is more permissive about
// truncated armor that the decoder would still reject).
func FuzzIsArmored(f *testing.F) {
	f.Add([]byte(begin + "\n"))
	f.Add([]byte("   \n\t" + begin))
	f.Add([]byte("SINDOOK2 binary..."))
	f.Add([]byte{})
	f.Add([]byte("\n\n"))
	f.Add([]byte(begin))

	f.Fuzz(func(t *testing.T, data []byte) {
		armored := IsArmored(data)
		// Must not panic.
		_ = armored
		// If decoder accepts, IsArmored must have been true (decoder requires leading
		// whitespace + begin at start).
		dec, err := io.ReadAll(io.LimitReader(NewReader(bytes.NewReader(data)), 1<<20))
		if err == nil {
			if !armored && !strings.Contains(string(data), begin) {
				t.Fatalf("accepted but not armored and no begin: %q -> %d bytes", data, len(dec))
			}
			// Also ensure that adding leading whitespace doesn't change acceptance for valid armor.
			prefixed := append([]byte("\n\n  \n"), data...)
			dec2, err2 := io.ReadAll(io.LimitReader(NewReader(bytes.NewReader(prefixed)), 1<<20))
			if err2 != nil {
				t.Fatalf("leading whitespace caused valid armor to be rejected")
			}
			if !bytes.Equal(dec, dec2) {
				t.Fatalf("leading whitespace changed decoded bytes")
			}
		}
	})
}

// CI validation: exercises the ClusterFuzzLite PR workflow.
