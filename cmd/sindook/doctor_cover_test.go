package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDoctorConfigStates walks the configuration-state matrix through
// SINDOOK_CONFIG_DIR: missing directory, empty directory, and a path that
// is a file rather than a directory.
func TestDoctorConfigStates(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(dir, "missing"))
	out, err := captureStdout(t, func() error { return cmdDoctor([]string{}) })
	if err != nil {
		t.Fatalf("doctor with missing config dir: %v", err)
	}
	if !strings.Contains(out, "not initialized") {
		t.Fatalf("missing dir should report not initialized:\n%s", out)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SINDOOK_CONFIG_DIR", empty)
	out, err = captureStdout(t, func() error { return cmdDoctor([]string{}) })
	if err != nil {
		t.Fatalf("doctor with empty config dir: %v", err)
	}
	if !strings.Contains(out, "has not been initialized") {
		t.Fatalf("empty dir should report uninitialized config:\n%s", out)
	}

	asFile := write(t, filepath.Join(dir, "not-a-dir"), []byte("x"))
	t.Setenv("SINDOOK_CONFIG_DIR", asFile)
	if err := cmdDoctor([]string{}); err == nil {
		t.Fatal("doctor accepted a config path that is a file")
	}
}

// TestDoctorJSONOutput covers the machine-readable report.
func TestDoctorJSONOutput(t *testing.T) {
	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(t.TempDir(), "missing"))
	out, err := captureStdout(t, func() error { return cmdDoctor([]string{"-json"}) })
	if err != nil {
		t.Fatalf("doctor -json: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("doctor JSON did not parse: %v\n%s", err, out)
	}
	if report.Version == "" || len(report.Checks) == 0 {
		t.Fatalf("doctor JSON incomplete: %+v", report)
	}
}

// TestDoctorUsageAndVersionCheck covers the usage guard and the
// update-check failure path (invalid SINDOOK_REPO fails before any
// network request).
func TestDoctorUsageAndVersionCheck(t *testing.T) {
	if err := cmdDoctor([]string{"unexpected"}); err == nil {
		t.Fatal("doctor accepted positional arguments")
	}

	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("SINDOOK_REPO", "not-a-repo")
	out, err := captureStdout(t, func() error { return cmdDoctor([]string{"-check-version"}) })
	if err != nil {
		t.Fatalf("doctor -check-version with invalid repo: %v", err)
	}
	if !strings.Contains(out, "could not check for updates") {
		t.Fatalf("expected update-check warning:\n%s", out)
	}
}
