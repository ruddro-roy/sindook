package box

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, errors.New("write failure") }

type failReader struct{}

// The error must not be io.EOF or io.ErrUnexpectedEOF: sealPayload treats
// both as legitimate end-of-input for the final chunk.
func (failReader) Read(p []byte) (int, error) { return 0, errors.New("read failure") }

// TestSealRecipientWrapperRoundTrip covers the public convenience wrapper,
// which nothing else in the package exercised.
func TestSealRecipientWrapperRoundTrip(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("seal-recipient wrapper round trip")
	var sealed bytes.Buffer
	if err := SealRecipient(&sealed, bytes.NewReader(msg), k.PublicKey()); err != nil {
		t.Fatalf("SealRecipient: %v", err)
	}
	var out bytes.Buffer
	if err := Open(&out, bytes.NewReader(sealed.Bytes()), k, nil); err != nil {
		t.Fatalf("Open after SealRecipient: %v", err)
	}
	if !bytes.Equal(out.Bytes(), msg) {
		t.Fatal("round trip mismatch through SealRecipient")
	}
}

// TestSelfTestRuns covers the in-library self test end to end.
func TestSelfTestRuns(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
}

func TestSealRejectsMalformedRecipient(t *testing.T) {
	err := Seal(io.Discard, strings.NewReader("x"), SealOptions{Recipients: [][]byte{make([]byte, 7)}})
	if err == nil {
		t.Fatal("Seal accepted a malformed recipient public key")
	}
}

func TestSealWriterFailure(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = Seal(failWriter{}, strings.NewReader("payload"), SealOptions{Recipients: [][]byte{k.PublicKey()}})
	if err == nil {
		t.Fatal("Seal succeeded despite a failing writer")
	}
}

func TestSealReaderFailure(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = Seal(io.Discard, failReader{}, SealOptions{Recipients: [][]byte{k.PublicKey()}})
	if err == nil {
		t.Fatal("Seal succeeded despite a failing reader")
	}
}

func TestOpenReaderFailure(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Open(io.Discard, failReader{}, k, nil); err == nil {
		t.Fatal("Open succeeded despite a failing reader")
	}
}

func TestRewrapErrorPaths(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	valid := SealOptions{Recipients: [][]byte{k.PublicKey()}}

	if err := Rewrap(io.Discard, strings.NewReader("x"), nil, nil,
		SealOptions{Recipients: [][]byte{make([]byte, 3)}}, false); err == nil {
		t.Fatal("Rewrap accepted a malformed recipient")
	}

	var sealed bytes.Buffer
	if err := Seal(&sealed, strings.NewReader("payload"), valid); err != nil {
		t.Fatal(err)
	}

	if err := Rewrap(io.Discard, strings.NewReader("not a sindook file"), nil, nil, valid, false); err == nil {
		t.Fatal("Rewrap accepted garbage input")
	}

	other, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Rewrap(io.Discard, bytes.NewReader(sealed.Bytes()), other, nil, valid, false); err == nil {
		t.Fatal("Rewrap unlocked with the wrong identity")
	}

	if err := Rewrap(failWriter{}, bytes.NewReader(sealed.Bytes()), k, nil, valid, false); err == nil {
		t.Fatal("Rewrap succeeded despite a failing writer")
	}
}

// TestWrapKeyLengthRejected covers the AEAD construction guards directly;
// the normal API cannot reach them because keys are always derived at
// the correct length.
func TestWrapKeyLengthRejected(t *testing.T) {
	if _, err := wrapSeal([]byte("short"), []byte("file key"), nil); err == nil {
		t.Fatal("wrapSeal accepted a short key")
	}
	if _, err := wrapOpen([]byte("short"), make([]byte, 48), nil); err == nil {
		t.Fatal("wrapOpen accepted a short key")
	}
}

// TestInspectTruncatedPrefixes feeds Inspect every prefix too short to
// contain even the fixed header fields; every one must fail structurally.
func TestInspectTruncatedPrefixes(t *testing.T) {
	k, err := xwing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := Seal(&sealed, strings.NewReader("payload"), SealOptions{Recipients: [][]byte{k.PublicKey()}}); err != nil {
		t.Fatal(err)
	}
	b := sealed.Bytes()
	for n := 0; n < 24; n++ {
		if _, err := Inspect(bytes.NewReader(b[:n])); err == nil {
			t.Fatalf("Inspect accepted a %d-byte truncation", n)
		}
	}
	if _, err := Inspect(bytes.NewReader(b)); err != nil {
		t.Fatalf("Inspect rejected the intact file: %v", err)
	}
}
