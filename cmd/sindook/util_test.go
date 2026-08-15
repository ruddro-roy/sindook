package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestParseInterspersedFlagsPreservesOperandsAndDelimiter(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	recipient := fs.String("r", "", "")
	parseInterspersedFlags(fs, []string{"report.txt", "-r", "alice.pub", "--", "-literal"})
	if *recipient != "alice.pub" {
		t.Fatalf("recipient = %q", *recipient)
	}
	if got, want := fs.Args(), []string{"report.txt", "-literal"}; !equalStrings(got, want) {
		t.Fatalf("operands = %#v, want %#v", got, want)
	}

	fs = flag.NewFlagSet("test", flag.ContinueOnError)
	parseInterspersedFlags(fs, []string{"--", "-literal"})
	if got, want := fs.Args(), []string{"-literal"}; !equalStrings(got, want) {
		t.Fatalf("leading-dash operand = %#v, want %#v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWithOutputForceFailurePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.txt")
	const old = "previous contents"
	if err := os.WriteFile(path, []byte(old), 0o640); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("write interrupted")
	err := withOutput(path, true, false, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial replacement"); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("withOutput error = %v, want %v", err, wantErr)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("existing output was not preserved: %v", err)
	}
	if string(got) != old {
		t.Fatalf("existing output = %q, want %q", got, old)
	}
}

func TestWithOutputForceRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("keep this"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "output.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	err := withOutput(link, true, false, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement")
		return err
	})
	if err == nil {
		t.Fatal("force output accepted a symlink")
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("force output replaced the symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep this" {
		t.Fatalf("symlink target = %q, want original contents", got)
	}
}

func TestOpenFailurePreservesForcedOutput(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "secret.txt"), []byte("sensitive text"))
	mustRun(t, cmdSeal, "-r", pub, in)

	sealed := in + ext
	raw, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(sealed, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	out := write(t, filepath.Join(dir, "out.txt"), []byte("previous output"))
	if err := cmdOpen([]string{"-i", key, "-o", out, "-f", sealed}); err == nil {
		t.Fatal("open accepted corrupted ciphertext")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "previous output" {
		t.Fatalf("forced output = %q, want previous output", got)
	}
}

func TestWriteFileNewForceRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.key")
	if err := os.WriteFile(target, []byte("existing identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "identity.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if err := writeFileNew(link, []byte("replacement identity"), 0o600, true); err == nil {
		t.Fatal("force identity write accepted a symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing identity" {
		t.Fatalf("symlink target = %q, want original contents", got)
	}
}
