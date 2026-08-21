package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/box"
)

func TestExitCode(t *testing.T) {
	ioErr := errors.New("plain io failure")
	joinedAuth := errors.Join(ioErr, errors.New("one file: bad identity"), box.ErrWrongKey)
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, 0},
		{"plain error is operational", ioErr, 1},
		{"payload corruption is operational", box.ErrPayloadCorrupted, 1},
		{"not a sindook file is operational", box.ErrNotSindook, 1},
		{"wrapped payload corruption is operational",
			fmt.Errorf("payload: %w", box.ErrPayloadCorrupted), 1},
		{"usage error", usagef("seal needs a recipient"), 2},
		{"joined usage beats operational",
			errors.Join(ioErr, usagef("bad flag combination")), 2},
		{"wrong key is authentication failure",
			fmt.Errorf("cannot open: %w", box.ErrWrongKey), 3},
		{"need identity is authentication failure", box.ErrNeedIdentity, 3},
		{"need passphrase is authentication failure", box.ErrNeedPassphrase, 3},
		{"tampered header is authentication failure", box.ErrHeaderTampered, 3},
		{"joined auth beats operational", joinedAuth, 3},
		{"joined usage beats auth",
			errors.Join(box.ErrWrongKey, usagef("provide -i IDENTITY, -p, or -passfile")), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestVerifyJSON exercises the machine-readable verify mode: one indented
// JSON array, every file reported, exit code reflecting any failure.
func TestVerifyJSON(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	good := write(t, filepath.Join(dir, "good.txt"), []byte("verified content"))
	mustRun(t, cmdSeal, "-r", pub, good)

	bad := write(t, filepath.Join(dir, "bad.txt"), []byte("will be corrupted"))
	mustRun(t, cmdSeal, "-r", pub, bad)
	raw, err := os.ReadFile(bad + ext)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-5] ^= 0x01
	write(t, bad+ext, raw)

	wrongKey, _ := newIdentity(t, dir, "stranger.key")

	var results []verifyResult
	decode := func(t *testing.T, out string) {
		t.Helper()
		if err := json.Unmarshal([]byte(out), &results); err != nil {
			t.Fatalf("verify -json output is not a JSON array: %v\n%s", err, out)
		}
		if !strings.HasPrefix(out, "[") {
			t.Fatalf("verify -json output should start with '[':\n%s", out)
		}
	}

	out, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-json", good + ext})
	})
	if err != nil {
		t.Fatalf("verify -json on a good file: %v", err)
	}
	decode(t, out)
	if len(results) != 1 || results[0].Status != "ok" || results[0].Error != "" {
		t.Fatalf("unexpected good-file result: %+v", results)
	}
	if strings.Contains(out, "ok\n") || strings.Contains(out, "FAILED") {
		t.Fatalf("verify -json leaked human-readable lines:\n%s", out)
	}

	out, err = captureStdout(t, func() error {
		return cmdVerify([]string{"-i", wrongKey, "-json", good + ext})
	})
	if err == nil {
		t.Fatal("verify -json accepted a wrong identity")
	}
	if code := exitCode(err); code != 3 {
		t.Errorf("exit code for wrong identity = %d, want 3", code)
	}
	decode(t, out)
	if len(results) != 1 || results[0].Status != "failed" || results[0].Error == "" {
		t.Fatalf("wrong identity result wrong: %+v", results)
	}

	out, err = captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-json", bad + ext, good + ext})
	})
	if err == nil {
		t.Fatal("verify -json accepted a corrupted file")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code for corrupted payload = %d, want 1", code)
	}
	decode(t, out)
	if len(results) != 2 {
		t.Fatalf("verify -json reported %d files, want 2", len(results))
	}
	if results[0].File != bad+ext || results[0].Status != "failed" || results[0].Error == "" {
		t.Fatalf("corrupted file result wrong: %+v", results[0])
	}
	if results[1].Status != "ok" {
		t.Fatalf("good file was not still verified: %+v", results[1])
	}

	missing := filepath.Join(dir, "missing.sindook")
	out, err = captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-json", missing})
	})
	if err == nil {
		t.Fatal("verify -json accepted a missing file")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code for missing file = %d, want 1", code)
	}
	decode(t, out)
	if len(results) != 1 || results[0].Status != "failed" || results[0].Error == "" {
		t.Fatalf("missing file result wrong: %+v", results)
	}
}
