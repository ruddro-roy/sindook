package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
