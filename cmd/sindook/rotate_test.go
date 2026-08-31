package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sealFor seals one plaintext file to pub and returns the sealed path.
func sealFor(t *testing.T, dir, name, pub, plaintext string) string {
	t.Helper()
	f := write(t, filepath.Join(dir, name), []byte(plaintext))
	mustRun(t, cmdSeal, "-r", pub, f)
	return f + ext
}

func TestRotateClassifiesRotatedSkippedFailed(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	newKey, newPub := newIdentity(t, dir, "new.key")

	mine := sealFor(t, dir, "mine.txt", oldPub, "sealed to the retired identity")
	other := sealFor(t, dir, "other.txt", newPub, "sealed to someone else")
	garbage := write(t, filepath.Join(dir, "garbage.sindook"), []byte("not a sindook file"))

	out, err := captureStdout(t, func() error {
		return cmdRotate([]string{"-i", oldKey, "-to", newPub, mine, other, garbage})
	})
	if err != nil {
		t.Fatalf("skipped files must not fail the run: %v", err)
	}
	if !strings.Contains(out, mine+": rotated") {
		t.Fatalf("file sealed to the retired identity not rotated:\n%s", out)
	}
	if !strings.Contains(out, other+": skipped (") {
		t.Fatalf("file sealed to another identity not skipped:\n%s", out)
	}
	if !strings.Contains(out, garbage+": skipped (") {
		t.Fatalf("garbage operand not skipped:\n%s", out)
	}

	// The retired identity must lose the rotated file, the new
	// recipient must gain it, and the plaintext must survive.
	if _, err := captureStdout(t, func() error { return cmdOpen([]string{"-i", oldKey, mine}) }); err == nil {
		t.Fatal("retired identity still opens the rotated file")
	}
	restore := filepath.Join(dir, "restored.txt")
	if _, err := captureStdout(t, func() error { return cmdOpen([]string{"-i", newKey, "-o", restore, mine}) }); err != nil {
		t.Fatalf("new recipient cannot open the rotated file: %v", err)
	}
	got, err := os.ReadFile(restore)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "sealed to the retired identity" {
		t.Fatalf("rotated file restored to %q", got)
	}

	// A skipped file is untouched.
	if _, err := captureStdout(t, func() error {
		return cmdVerify([]string{"-i", newKey, other})
	}); err != nil {
		t.Fatalf("skipped file damaged by rotate: %v", err)
	}
}

func TestRotateDeepAndFastBothDropOldSlot(t *testing.T) {
	for _, deep := range []bool{false, true} {
		dir := t.TempDir()
		oldKey, oldPub := newIdentity(t, dir, "old.key")
		newKey, newPub := newIdentity(t, dir, "new.key")
		sealed := sealFor(t, dir, "data.bin", oldPub, "payload for rotation")

		args := []string{"-i", oldKey, "-to", newPub}
		if deep {
			args = append(args, "-deep")
		}
		args = append(args, sealed)
		if _, err := captureStdout(t, func() error { return cmdRotate(args) }); err != nil {
			t.Fatalf("deep=%v: %v", deep, err)
		}

		if _, err := captureStdout(t, func() error { return cmdOpen([]string{"-i", oldKey, sealed}) }); err == nil {
			t.Fatalf("deep=%v: retired identity still opens the replacement", deep)
		}
		restore := filepath.Join(dir, "out.bin")
		if _, err := captureStdout(t, func() error { return cmdOpen([]string{"-i", newKey, "-o", restore, sealed}) }); err != nil {
			t.Fatalf("deep=%v: new recipient cannot open the replacement: %v", deep, err)
		}
		got, err := os.ReadFile(restore)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "payload for rotation" {
			t.Fatalf("deep=%v: plaintext changed to %q", deep, got)
		}
	}
}

func TestRotateJobsMatchesSerial(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	_, newPub := newIdentity(t, dir, "new.key")

	sub := filepath.Join(dir, "nest")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		p := sealFor(t, sub, n+".txt", oldPub, "payload "+n)
		names = append(names, p)
	}
	write(t, filepath.Join(sub, "ignore.txt"), []byte("not sealed, wrong suffix"))

	// Each run needs its own tree: rotation is in-place, so the second run
	// would find everything already rotated.
	run := func(root string, extra ...string) (string, error) {
		args := append([]string{"-i", oldKey, "-to", newPub}, extra...)
		args = append(args, root)
		return captureStdout(t, func() error { return cmdRotate(args) })
	}
	serialDir := filepath.Join(dir, "serial")
	if err := os.MkdirAll(filepath.Join(serialDir, "nest"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		sealFor(t, filepath.Join(serialDir, "nest"), n+".txt", oldPub, "payload "+n)
	}

	parallel, err := run(sub, "-jobs", "4")
	if err != nil {
		t.Fatalf("parallel rotate: %v", err)
	}
	serial, err := run(serialDir, "-jobs", "1")
	if err != nil {
		t.Fatalf("serial rotate: %v", err)
	}
	// The two trees have different parent directories, so compare the
	// per-file suffixes rather than whole lines.
	strip := func(out, root string) []string {
		var lines []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line == "" {
				continue
			}
			lines = append(lines, strings.TrimPrefix(line, root))
		}
		return lines
	}
	pl, sl := strip(parallel, sub), strip(serial, filepath.Join(serialDir, "nest"))
	if len(pl) != len(sl) {
		t.Fatalf("line counts differ:\nparallel:\n%s\nserial:\n%s", parallel, serial)
	}
	for i := range pl {
		if pl[i] != sl[i] {
			t.Fatalf("parallel output differs from serial at %d:\nparallel:\n%s\nserial:\n%s", i, parallel, serial)
		}
	}
	// Walk output must be sorted, and the wrong-suffix file never attempted.
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if !strings.Contains(parallel, "/"+n+".txt.sindook: rotated") {
			t.Fatalf("%s missing from walk output:\n%s", n, parallel)
		}
	}
	if strings.Contains(parallel, "ignore.txt") {
		t.Fatalf("non-.sindook file attempted during walk:\n%s", parallel)
	}
}

func TestRotateJSONReport(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	_, newPub := newIdentity(t, dir, "new.key")
	mine := sealFor(t, dir, "mine.txt", oldPub, "json payload")
	other := sealFor(t, dir, "other.txt", newPub, "other payload")

	out, err := captureStdout(t, func() error {
		return cmdRotate([]string{"-i", oldKey, "-to", newPub, "-json", mine, other})
	})
	if err != nil {
		t.Fatal(err)
	}
	var results []rotateResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("rotate -json is not a JSON array: %v\n%s", err, out)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 rows, got %d:\n%s", len(results), out)
	}
	byFile := map[string]rotateResult{}
	for _, r := range results {
		byFile[r.File] = r
	}
	if byFile[mine].Status != "rotated" || byFile[mine].Error != "" {
		t.Fatalf("rotated row wrong: %+v", byFile[mine])
	}
	if byFile[other].Status != "skipped" || byFile[other].Error == "" {
		t.Fatalf("skipped row must carry its reason: %+v", byFile[other])
	}
}

func TestRotateFailedWriteLeavesOriginalIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory chmod does not restrict creation on Windows")
	}
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	_, newPub := newIdentity(t, dir, "new.key")
	sealed := sealFor(t, dir, "locked.txt", oldPub, "must survive a failed write")
	before, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	out, err := captureStdout(t, func() error {
		return cmdRotate([]string{"-i", oldKey, "-to", newPub, sealed})
	})
	if err == nil {
		t.Fatal("a failed rewrap must fail the run")
	}
	if !strings.Contains(out, sealed+": FAILED") {
		t.Fatalf("failed file not reported:\n%s", out)
	}
	if exitCode(err) != 1 {
		t.Fatalf("failed write should exit 1, got %d via %v", exitCode(err), err)
	}
	after, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("original file changed during a failed rotate")
	}
}

func TestRotateUsageErrors(t *testing.T) {
	dir := t.TempDir()
	oldKey, _ := newIdentity(t, dir, "old.key")

	cases := [][]string{
		{"-to", "alice.pub", "x.sindook"},
		{"-i", oldKey, "x.sindook"},
		{"-i", oldKey, "-to", "alice.pub", "-jobs", "-1", "x.sindook"},
		{"-i", oldKey, "-to", "alice.pub", "-"},
	}
	for _, args := range cases {
		if _, err := captureStdout(t, func() error { return cmdRotate(args) }); err == nil || exitCode(err) != 2 {
			t.Fatalf("args %v: want usage error, got %v", args, err)
		}
	}
}
