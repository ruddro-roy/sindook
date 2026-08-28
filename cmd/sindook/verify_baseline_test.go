package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestVerifyBaselineSaveAndCompare(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdKeygen, "-o", key)
	a := write(t, filepath.Join(dir, "a.txt"), []byte("alpha"))
	b := write(t, filepath.Join(dir, "b.txt"), []byte("bravo"))
	mustRun(t, cmdSeal, "-r", key+".pub", a, b)

	base := filepath.Join(dir, "baseline.json")
	mustRun(t, cmdVerify, "-i", key, "-save", base, a+ext, b+ext)

	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	var saved verifyBaseline
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Version != baselineVersion || len(saved.Entries) != 2 {
		t.Fatalf("saved baseline = %+v", saved)
	}
	wantSHA := fileSHA256(t, a+ext)
	if saved.Entries[0].SHA256 != wantSHA {
		t.Fatalf("baseline sha256 = %s, want %s", saved.Entries[0].SHA256, wantSHA)
	}

	out, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-baseline", base, "-json", a + ext, b + ext})
	})
	if err != nil {
		t.Fatal(err)
	}
	var results []verifyResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		if res.Status != "ok" || res.BaselineSHA256 == "" || res.SHA256 != res.BaselineSHA256 {
			t.Fatalf("expected unchanged ok result, got %+v", res)
		}
	}

	human, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-baseline", base, a + ext})
	})
	if err != nil || !strings.Contains(human, "ok (unchanged)") {
		t.Fatalf("human baseline output = %q, %v", human, err)
	}
}

func TestVerifyBaselineDetectsChangeNewMissingFailed(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdKeygen, "-o", key)
	a := write(t, filepath.Join(dir, "a.txt"), []byte("alpha"))
	b := write(t, filepath.Join(dir, "b.txt"), []byte("bravo"))
	c := write(t, filepath.Join(dir, "c.txt"), []byte("charlie"))
	mustRun(t, cmdSeal, "-r", key+".pub", a, b, c)

	base := filepath.Join(dir, "baseline.json")
	mustRun(t, cmdVerify, "-i", key, "-save", base, a+ext, b+ext)

	// changed: b re-sealed under a fresh random file key, still a valid file.
	mustRun(t, cmdSeal, "-r", key+".pub", "-f", b)
	// failed: a corrupted by appending a byte, which fails authentication.
	appendTamper(t, a+ext)
	// new: c was never in the baseline.
	// missing: baseline is checked bare below, so entries absent from disk
	// surface as missing.

	out, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-baseline", base, "-json", a + ext, b + ext, c + ext})
	})
	if err == nil {
		t.Fatal("baseline run with a corrupted file must exit non-zero")
	}
	var results []verifyResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatal(err)
	}
	byFile := map[string]verifyResult{}
	for _, res := range results {
		byFile[res.File] = res
	}
	if got := byFile[a+ext].Status; got != "failed" {
		t.Errorf("corrupted file status = %q, want failed", got)
	}
	if got := byFile[a+ext].BaselineSHA256; got == "" {
		t.Error("failed result lost the baseline digest")
	}
	if got := byFile[b+ext].Status; got != "changed" {
		t.Errorf("re-sealed file status = %q, want changed", got)
	}
	if got := byFile[c+ext].Status; got != "new" {
		t.Errorf("unbaselined file status = %q, want new", got)
	}

	// Bare -baseline run: verifies the recorded set and reports deletions.
	if err := os.Remove(a + ext); err != nil {
		t.Fatal(err)
	}
	human, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-baseline", base})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human, "MISSING (in baseline)") {
		t.Fatalf("missing not reported: %q", human)
	}
	if !strings.Contains(human, "CHANGED since baseline") {
		t.Fatalf("changed not reported: %q", human)
	}
}

func TestVerifyBaselineSaveExcludesFailuresAndFlagGuards(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdKeygen, "-o", key)
	a := write(t, filepath.Join(dir, "a.txt"), []byte("alpha"))
	mustRun(t, cmdSeal, "-r", key+".pub", a)
	appendTamper(t, a+ext)

	base := filepath.Join(dir, "baseline.json")
	if err := cmdVerify([]string{"-i", key, "-save", base, a + ext}); err == nil {
		t.Fatal("saving a baseline over a failed verification must exit non-zero")
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	var saved verifyBaseline
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Entries) != 0 {
		t.Fatalf("failed file must not enter the baseline, got %+v", saved.Entries)
	}

	if _, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-save", base, "-baseline", base})
	}); err == nil || exitCode(err) != 2 {
		t.Fatalf("-save with -baseline: got %v, want usage error", err)
	}

	bad := filepath.Join(dir, "bad.json")
	write(t, bad, []byte(`{"version": 99, "entries": []}`))
	if _, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-baseline", bad})
	}); err == nil || !strings.Contains(err.Error(), "unsupported baseline version") {
		t.Fatalf("unknown baseline version: got %v", err)
	}
}

// appendTamper extends a sealed file so chunk authentication fails.
func appendTamper(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, 0x00), 0o600); err != nil {
		t.Fatal(err)
	}
}
