package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/internal/baseline"
)

// TestVerifyJobsMatchesSerial verifies many files serially and with -jobs,
// and requires identical output, identical JSON, and identical baselines:
// the worker pool is a scheduling detail, not a behavioral one.
func TestVerifyJobsMatchesSerial(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	var sealed []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		f := write(t, filepath.Join(dir, n+".txt"), []byte("payload "+n))
		mustRun(t, cmdSeal, "-r", pub, f)
		sealed = append(sealed, f+ext)
	}

	run := func(extra ...string) (string, error) {
		args := append([]string{"-i", key}, extra...)
		args = append(args, sealed...)
		return captureStdout(t, func() error { return cmdVerify(args) })
	}
	serial, err := run("-jobs", "1")
	if err != nil {
		t.Fatalf("serial verify: %v", err)
	}
	parallel, err := run("-jobs", "4")
	if err != nil {
		t.Fatalf("parallel verify: %v", err)
	}
	auto, err := run()
	if err != nil {
		t.Fatalf("default verify: %v", err)
	}
	if parallel != serial || auto != serial {
		t.Fatalf("parallel output differs from serial:\nserial:\n%s\nparallel:\n%s\ndefault:\n%s", serial, parallel, auto)
	}
	// Output order must follow the operand order, not completion order.
	offset := 0
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		i := strings.Index(serial[offset:], filepath.Join(dir, n+".txt.sindook")+": ok")
		if i < 0 {
			t.Fatalf("%s: missing ok line in output:\n%s", n, serial)
		}
		offset += i
	}

	js, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "1", "-json"}, sealed...))
	})
	if err != nil {
		t.Fatal(err)
	}
	jp, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "4", "-json"}, sealed...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if jp != js {
		t.Fatalf("parallel JSON differs from serial:\nserial:\n%s\nparallel:\n%s", js, jp)
	}

	// -save with workers produces the same baseline as serially.
	saveSerial := filepath.Join(dir, "serial.json")
	saveParallel := filepath.Join(dir, "parallel.json")
	if _, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "1", "-save", saveSerial}, sealed...))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "4", "-save", saveParallel}, sealed...))
	}); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(saveSerial)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(saveParallel)
	if err != nil {
		t.Fatal(err)
	}
	// created_at/verified_at timestamps differ between runs; the entry sets
	// must still match exactly.
	var ba, bb baseline.Record
	if err := json.Unmarshal(a, &ba); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &bb); err != nil {
		t.Fatal(err)
	}
	if len(ba.Entries) != len(bb.Entries) {
		t.Fatalf("baseline entry counts differ: %d vs %d", len(ba.Entries), len(bb.Entries))
	}
	for i := range ba.Entries {
		if ba.Entries[i].File != bb.Entries[i].File || ba.Entries[i].SHA256 != bb.Entries[i].SHA256 {
			t.Fatalf("baseline entries differ at %d: %+v vs %+v", i, ba.Entries[i], bb.Entries[i])
		}
	}
}

// TestVerifyJobsParallelFailure keeps the failure contract: one corrupt
// file fails the run and is reported, every other file still verifies.
func TestVerifyJobsParallelFailure(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	good := write(t, filepath.Join(dir, "good.txt"), []byte("intact"))
	bad := write(t, filepath.Join(dir, "bad.txt"), []byte("tampered"))
	mustRun(t, cmdSeal, "-r", pub, good, bad)
	appendTamper(t, bad+ext)

	out, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-jobs", "4", good + ext, bad + ext})
	})
	if err == nil {
		t.Fatal("verify passed a corrupted file")
	}
	if !strings.Contains(out, good+ext+": ok") {
		t.Fatalf("healthy file not verified ok:\n%s", out)
	}
	if !strings.Contains(out, bad+ext+": FAILED") {
		t.Fatalf("corrupted file not reported FAILED:\n%s", out)
	}
	if !strings.Contains(err.Error(), bad+ext) {
		t.Fatalf("joined error lost the failing file: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", key, "-jobs", "-2", good + ext})
	}); err == nil || exitCode(err) != 2 {
		t.Fatalf("negative -jobs: got %v, want usage error", err)
	}
}

// TestVerifyJobsBaselineReuse re-verifies a baseline's recorded set with
// workers and requires unchanged files to still read as unchanged.
func TestVerifyJobsBaselineReuse(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	base := filepath.Join(dir, "base.json")
	var sealed []string
	for _, n := range []string{"one", "two", "three", "four"} {
		f := write(t, filepath.Join(dir, n+".txt"), []byte("data "+n))
		mustRun(t, cmdSeal, "-r", pub, f)
		sealed = append(sealed, f+ext)
	}
	if _, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "4", "-save", base}, sealed...))
	}); err != nil {
		t.Fatal(err)
	}

	// Rewrap one file (same recipient, different ciphertext bytes), drop
	// another; the pooled comparison must spot both kinds of drift and keep
	// the rest unchanged.
	mustRun(t, cmdRewrap, "-i", key, "-r", pub, sealed[1])
	if err := os.Remove(sealed[2]); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return cmdVerify(append([]string{"-i", key, "-jobs", "2", "-baseline", base}, sealed...))
	})
	if err != nil {
		t.Fatalf("baseline drift must not fail the run: %v", err)
	}
	if !strings.Contains(out, sealed[0]+": ok (unchanged)") || !strings.Contains(out, sealed[3]+": ok (unchanged)") {
		t.Fatalf("healthy files not unchanged:\n%s", out)
	}
	if !strings.Contains(out, sealed[1]+": CHANGED") {
		t.Fatalf("changed file not reported:\n%s", out)
	}
	if !strings.Contains(out, sealed[2]+": MISSING") {
		t.Fatalf("baseline-only file not reported missing:\n%s", out)
	}
}
