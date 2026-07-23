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
