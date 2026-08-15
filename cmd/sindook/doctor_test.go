package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
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

func TestReleaseIsNewer(t *testing.T) {
	for _, test := range []struct {
		candidate, current string
		newer, comparable  bool
	}{
		{"v0.5.1", "0.5.0", true, true},
		{"v1.0.0", "1.0.0", false, true},
		{"v0.4.9", "0.5.0", false, true},
		{"latest", "0.5.0", false, false},
	} {
		newer, comparable := releaseIsNewer(test.candidate, test.current)
		if newer != test.newer || comparable != test.comparable {
			t.Errorf("releaseIsNewer(%q, %q) = (%v, %v), want (%v, %v)", test.candidate, test.current, newer, comparable, test.newer, test.comparable)
		}
	}
}
