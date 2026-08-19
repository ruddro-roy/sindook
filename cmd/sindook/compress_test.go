package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Compression round trip across multiple 64 KiB payload chunks. The sealed
// file must be smaller than the plaintext for repetitive input, proving the
// compression actually happened before encryption.
func TestCompressionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	plain := bytes.Repeat([]byte("compress me "), 30_000) // ~352 KiB, several chunks
	in := write(t, filepath.Join(dir, "data.bin"), plain)

	mustRun(t, cmdSeal, "-r", pub, "-z", in)
	sealed, err := os.ReadFile(in + ext)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) >= len(plain) {
		t.Fatalf("compressed sealed file is %d bytes, expected smaller than the %d byte plaintext", len(sealed), len(plain))
	}

	out := filepath.Join(dir, "out.bin")
	mustRun(t, cmdOpen, "-i", key, "-z", "-o", out, in+ext)
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("decompressed round trip mismatch: %v", err)
	}
}

// Opening a compressed file without -z yields the raw gzip stream, so the
// bytes are still intact and recoverable with gunzip or open -z.
func TestOpenCompressedWithoutFlagProducesGzip(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "data.bin"), bytes.Repeat([]byte("round "), 5_000))

	mustRun(t, cmdSeal, "-r", pub, "-z", in)
	out := filepath.Join(dir, "out.gz")
	mustRun(t, cmdOpen, "-i", key, "-o", out, in+ext)

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || got[0] != 0x1f || got[1] != 0x8b {
		t.Fatalf("output without -z starts with %x..., want gzip magic 1f 8b", got)
	}
}

// Opening an uncompressed file with -z fails with a message that names the
// flag, instead of writing a confusing partial output.
func TestOpenUncompressedWithZFlagFails(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "plain.txt"), []byte("not compressed"))

	mustRun(t, cmdSeal, "-r", pub, in)
	out := filepath.Join(dir, "out.txt")
	err := cmdOpen([]string{"-i", key, "-z", "-o", out, in + ext})
	if err == nil || !strings.Contains(err.Error(), "-z") {
		t.Fatalf("open -z on an uncompressed file: err = %v, want a message mentioning -z", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatalf("failed open -z left an output file behind")
	}
}

// Armor and compression combine: ASCII output on seal, transparent armor
// detection plus decompression on open.
func TestArmoredCompressionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "data.bin"), bytes.Repeat([]byte("armored "), 10_000))

	armored := filepath.Join(dir, "data.arm")
	mustRun(t, cmdSeal, "-r", pub, "-z", "-a", "-o", armored, in)
	raw, err := os.ReadFile(armored)
	if err != nil || !bytes.HasPrefix(raw, []byte("-----BEGIN")) {
		t.Fatalf("armored compressed output missing armor header: %v", err)
	}

	out := filepath.Join(dir, "out.bin")
	mustRun(t, cmdOpen, "-i", key, "-z", "-o", out, armored)
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("armored "), 10_000)) {
		t.Fatalf("armored compressed round trip mismatch (%d bytes)", len(got))
	}
}

// A gzip stream with a valid header but corrupt deflate data, larger than
// the 64 KiB pipe buffer, sealed as a normal file and then opened with -z.
// The decompressor stops early; before the reader-side close fix, box.Open
// blocked forever on the full pipe. This regression test fails as a timeout
// if the deadlock returns.
func TestOpenCorruptGzipLargeDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")

	// Valid gzip header, then garbage well past the pipe buffer size.
	var bomb bytes.Buffer
	gz := gzip.NewWriter(&bomb)
	if _, err := gz.Write(bytes.Repeat([]byte("x"), 512<<10)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	hostile := bomb.Bytes()[:1<<10] // header plus a slice of the stream
	hostile = append(hostile, bytes.Repeat([]byte{0xA7}, 512<<10)...)

	in := write(t, filepath.Join(dir, "hostile.bin"), hostile)
	mustRun(t, cmdSeal, "-r", pub, in)

	done := make(chan error, 1)
	go func() {
		done <- cmdOpen([]string{"-i", key, "-z", "-o", filepath.Join(dir, "out"), in + ext})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("open -z on corrupt gzip unexpectedly succeeded")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("open -z deadlocked on corrupt gzip data")
	}
}

// A small sealed file whose gzip payload expands far beyond a low
// -max-decompressed limit must fail with the limit error, not expand.
func TestMaxDecompressedLimitStopsBomb(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")

	var bomb bytes.Buffer
	gz := gzip.NewWriter(&bomb)
	if _, err := gz.Write(bytes.Repeat([]byte{0}, 64<<20)); err != nil { // 64 MiB of zeros
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	in := write(t, filepath.Join(dir, "bomb.gz"), bomb.Bytes())
	mustRun(t, cmdSeal, "-r", pub, in)

	out := filepath.Join(dir, "out")
	err := cmdOpen([]string{"-i", key, "-z", "-max-decompressed", "1M", "-o", out, in + ext})
	if !errors.Is(err, errDecompressedTooLarge) {
		t.Fatalf("open -z beyond the limit: err = %v, want errDecompressedTooLarge", err)
	}
	info, statErr := os.Stat(out)
	if statErr == nil && info.Size() > 2<<20 {
		t.Fatalf("limit writer wrote %d bytes despite the 1 MiB limit", info.Size())
	}
	if _, statErr := os.Stat(out); statErr == nil {
		// The partial output must have been removed on failure.
		t.Fatalf("failed open -z left partial output %s behind", out)
	}

	// Raising the limit to unlimited completes the expansion.
	mustRun(t, cmdOpen, "-i", key, "-z", "-max-decompressed", "0", "-o", out, in+ext)
	got, err := os.ReadFile(out)
	if err != nil || len(got) != 64<<20 {
		t.Fatalf("unlimited open -z: %d bytes, err %v", len(got), err)
	}
}

// verify -z proves a compressed archive is fully recoverable, including its
// gzip checksum, and applies the same decompressed-size limit.
func TestVerifyDecompresses(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(bytes.Repeat([]byte("verify me "), 40_000)); err != nil {
		t.Fatal(err)
	}
	_ = gz.Close()
	in := write(t, filepath.Join(dir, "data.gz"), buf.Bytes())
	// Seal the gzip bytes as-is (no -z), so verify -z decompresses the
	// single real layer, exactly like a file that will be opened with -z.
	mustRun(t, cmdSeal, "-r", pub, in)

	mustRun(t, cmdVerify, "-z", "-i", key, in+ext)

	err := cmdVerify([]string{"-z", "-i", key, "-max-decompressed", "1K", in + ext})
	if !errors.Is(err, errDecompressedTooLarge) {
		t.Fatalf("verify -z beyond the limit: err = %v, want errDecompressedTooLarge", err)
	}
}

func TestParseSize(t *testing.T) {
	good := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"1024", 1024},
		{"1k", 1 << 10},
		{"2K", 2 << 10},
		{"512KiB", 512 << 10},
		{"1m", 1 << 20},
		{"3MiB", 3 << 20},
		{"1g", 1 << 30},
		{"2GiB", 2 << 30},
		{"1t", 1 << 40},
		{"1T", 1 << 40},
		{" 4G ", 4 << 30},
		{"100b", 100},
	}
	for _, tc := range good {
		got, err := parseSize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	bad := []string{"", "-1", "1x", "1.5G", "G", "9999999999999999999999"}
	for _, in := range bad {
		if got, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", in, got)
		}
	}
}
