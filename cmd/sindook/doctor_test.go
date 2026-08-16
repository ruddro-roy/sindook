package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/internal/memguard"
)

func runDoctorJSON(t *testing.T, args ...string) (doctorReport, error) {
	t.Helper()
	args = append(args, "-json")
	out, err := captureStdout(t, func() error { return cmdDoctor(args) })
	var report doctorReport
	if decodeErr := json.Unmarshal([]byte(out), &report); decodeErr != nil {
		t.Fatalf("doctor JSON output: %v\n%s", decodeErr, out)
	}
	return report, err
}

func TestDoctorFreshConfigIsHealthy(t *testing.T) {
	dir := configEnv(t)
	report, err := runDoctorJSON(t)
	if err != nil {
		t.Fatal(err)
	}
	// The memory lock check depends on the host's RLIMIT_MEMLOCK, so it is
	// excluded from the healthy-report assertion.
	for _, check := range report.Checks {
		if check.Name == "memory lock" {
			continue
		}
		if check.Status == "error" || check.Status == "warning" {
			t.Fatalf("fresh doctor report = %+v", report)
		}
	}
	if report.Errors != 0 {
		t.Fatalf("fresh doctor report = %+v", report)
	}
	if report.ConfigDirectory != dir || report.ConfigFile != filepath.Join(dir, "config.json") {
		t.Fatalf("doctor config paths = %q, %q", report.ConfigDirectory, report.ConfigFile)
	}
}

func TestDoctorReportsMissingDefaultIdentity(t *testing.T) {
	configEnv(t)
	missing := filepath.Join(t.TempDir(), "missing.key")
	if err := setDefaultIdentity(missing); err != nil {
		t.Fatal(err)
	}
	report, err := runDoctorJSON(t)
	if err == nil {
		t.Fatal("doctor succeeded with a missing selected identity")
	}
	if report.Errors != 1 {
		t.Fatalf("doctor errors = %d, want 1; report=%+v", report.Errors, report)
	}
}

// TestDoctorOperationalErrorExitCode: a doctor run with errors returns a
// non-nil error that maps to the operational exit code 1. The other
// exit-code classes (nil=0, usage=2, wrong key=3) are covered in
// exitcode_test.go.
func TestDoctorOperationalErrorExitCode(t *testing.T) {
	configEnv(t)
	missing := filepath.Join(t.TempDir(), "missing.key")
	if err := setDefaultIdentity(missing); err != nil {
		t.Fatal(err)
	}
	_, err := runDoctorJSON(t)
	if err == nil {
		t.Fatal("doctor succeeded with a missing selected identity")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exitCode(doctor error) = %d, want 1", code)
	}
}

// TestDoctorMemoryLockUnsupportedIsWarning pins the ErrUnsupported path:
// an unsupported memory-locking platform is a warning, never an error, and
// warnings alone are not fatal.
func TestDoctorMemoryLockUnsupportedIsWarning(t *testing.T) {
	configEnv(t)
	orig := lockAll
	lockAll = func() error { return memguard.ErrUnsupported }
	defer func() { lockAll = orig }()

	report, err := runDoctorJSON(t)
	if err != nil {
		t.Fatalf("doctor with warnings only must return nil, got %v", err)
	}
	check := findDoctorCheck(t, report, "memory lock")
	if check.Status != "warning" {
		t.Errorf("memory lock status = %q, want %q", check.Status, "warning")
	}
	if check.Remediation == "" {
		t.Error("memory lock warning should carry a remediation")
	}
	if report.Errors != 0 {
		t.Errorf("doctor errors = %d, want 0; report=%+v", report.Errors, report)
	}
	if report.Warnings < 1 {
		t.Errorf("doctor warnings = %d, want >= 1; report=%+v", report.Warnings, report)
	}
}

// TestDoctorMemoryLockDeniedIsWarning pins the generic-lock-failure path:
// a denied mlock is reported as a warning with the failure detail and a
// remediation, and is still not fatal.
func TestDoctorMemoryLockDeniedIsWarning(t *testing.T) {
	configEnv(t)
	orig := lockAll
	lockAll = func() error { return errors.New("memlock denied") }
	defer func() { lockAll = orig }()

	report, err := runDoctorJSON(t)
	if err != nil {
		t.Fatalf("doctor with warnings only must return nil, got %v", err)
	}
	check := findDoctorCheck(t, report, "memory lock")
	if check.Status != "warning" {
		t.Errorf("memory lock status = %q, want %q", check.Status, "warning")
	}
	if !strings.Contains(check.Detail, "memlock denied") {
		t.Errorf("memory lock detail = %q, want it to carry the lock error", check.Detail)
	}
	if check.Remediation == "" {
		t.Error("memory lock warning should carry a remediation")
	}
	if report.Errors != 0 {
		t.Errorf("doctor errors = %d, want 0; report=%+v", report.Errors, report)
	}
	if report.Warnings < 1 {
		t.Errorf("doctor warnings = %d, want >= 1; report=%+v", report.Warnings, report)
	}
}

// TestDoctorReportsMissingPublicKeyWithWorkingRemediation covers the
// missing <identity>.pub diagnostic and positively validates its
// remediation: "sindook pubkey @default" must be the exact accepted
// invocation and must print a parseable public key.
func TestDoctorReportsMissingPublicKeyWithWorkingRemediation(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	key, _ := newIdentity(t, dir, "id.key")
	if err := os.Remove(key + ".pub"); err != nil {
		t.Fatal(err)
	}
	if err := setDefaultIdentity(key); err != nil {
		t.Fatal(err)
	}

	report, err := runDoctorJSON(t)
	if err != nil {
		t.Fatalf("a missing .pub is a warning, not fatal: %v", err)
	}
	check := findDoctorCheck(t, report, "default public key")
	if check.Status != "warning" {
		t.Errorf("default public key status = %q, want %q", check.Status, "warning")
	}
	if !strings.Contains(check.Remediation, "sindook pubkey @default") {
		t.Errorf("remediation = %q, want it to contain %q", check.Remediation, "sindook pubkey @default")
	}
	if report.Errors != 0 {
		t.Errorf("doctor errors = %d, want 0; report=%+v", report.Errors, report)
	}

	// Positively validate the remediation: run the exact pubkey invocation
	// and require a parseable sindook public key on stdout.
	out, err := captureStdout(t, func() error { return cmdPubkey([]string{"@default"}) })
	if err != nil {
		t.Fatalf("remediation command 'sindook pubkey @default' failed: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), pkPrefix) {
		t.Errorf("pubkey @default output = %q, want a %s public key", out, pkPrefix)
	}
	if _, err := loadRecipient(strings.TrimSpace(out)); err != nil {
		t.Errorf("pubkey @default output does not parse: %v", err)
	}
}

func findDoctorCheck(t *testing.T, report doctorReport, name string) *doctorCheck {
	t.Helper()
	for i := range report.Checks {
		if report.Checks[i].Name == name {
			return &report.Checks[i]
		}
	}
	t.Fatalf("no %q check in report: %+v", name, report)
	return nil
}

func TestReleaseIsNewer(t *testing.T) {
	for _, test := range []struct {
		candidate, current string
		newer, comparable  bool
	}{
		{"v0.7.1", "0.7.0", true, true},
		{"v1.0.0", "1.0.0", false, true},
		{"v0.6.9", "0.7.0", false, true},
		{"latest", "0.7.0", false, false},
	} {
		newer, comparable := releaseIsNewer(test.candidate, test.current)
		if newer != test.newer || comparable != test.comparable {
			t.Errorf("releaseIsNewer(%q, %q) = (%v, %v), want (%v, %v)", test.candidate, test.current, newer, comparable, test.newer, test.comparable)
		}
	}
}
