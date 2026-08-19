package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/internal/memguard"
)

// The suite drives the real cmd* entry points with temp files; passphrases
// always come from -passfile so no test needs a terminal.

func write(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustRun(t *testing.T, f func([]string) error, args ...string) {
	t.Helper()
	if err := f(args); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
}

func newIdentity(t *testing.T, dir, name string) (keyPath, pubPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, name)
	mustRun(t, cmdKeygen, "-o", keyPath)
	return keyPath, keyPath + ".pub"
}

func TestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	plain := bytes.Repeat([]byte("round trip "), 20_000) // multiple chunks
	in := write(t, filepath.Join(dir, "data.bin"), plain)

	mustRun(t, cmdSeal, "-r", pub, in)
	mustRun(t, cmdOpen, "-i", key, "-o", filepath.Join(dir, "out.bin"), in+ext)

	got, err := os.ReadFile(filepath.Join(dir, "out.bin"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %v", err)
	}
}

func TestArmorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "note.txt"), []byte("armored secret"))

	mustRun(t, cmdSeal, "-r", pub, "-a", in)
	sealed, err := os.ReadFile(in + ext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(sealed), "-----BEGIN SINDOOK ENCRYPTED FILE-----") {
		t.Fatalf("not armored:\n%s", sealed)
	}
	mustRun(t, cmdOpen, "-i", key, "-o", filepath.Join(dir, "note.out"), in+ext)
	got, _ := os.ReadFile(filepath.Join(dir, "note.out"))
	if string(got) != "armored secret" {
		t.Fatalf("armor round trip mismatch: %q", got)
	}
}

func TestMultiFileSealOpenVerify(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	var files []string
	for _, n := range []string{"a", "b", "c"} {
		files = append(files, write(t, filepath.Join(dir, n+".txt"), []byte("file "+n)))
	}

	mustRun(t, cmdSeal, append([]string{"-r", pub}, files...)...)
	var sealed []string
	for _, f := range files {
		sealed = append(sealed, f+ext)
	}
	mustRun(t, cmdVerify, append([]string{"-i", key}, sealed...)...)
	mustRun(t, cmdOpen, append([]string{"-i", key, "-f"}, sealed...)...)
	for _, f := range files {
		got, err := os.ReadFile(f)
		if err != nil || string(got) != "file "+filepath.Base(f[:len(f)-4]) {
			t.Fatalf("%s: %q %v", f, got, err)
		}
	}
}

func TestPassphraseFlow(t *testing.T) {
	dir := t.TempDir()
	passfile := write(t, filepath.Join(dir, "pass"), []byte("correct horse\n"))
	in := write(t, filepath.Join(dir, "notes.txt"), []byte("pass protected"))

	mustRun(t, cmdSeal, "-passfile", passfile, in)
	mustRun(t, cmdVerify, "-passfile", passfile, in+ext)
	mustRun(t, cmdOpen, "-passfile", passfile, "-o", filepath.Join(dir, "notes.out"), in+ext)
	got, _ := os.ReadFile(filepath.Join(dir, "notes.out"))
	if string(got) != "pass protected" {
		t.Fatalf("mismatch: %q", got)
	}

	wrong := write(t, filepath.Join(dir, "wrong"), []byte("not it\n"))
	if err := cmdVerify([]string{"-passfile", wrong, in + ext}); err == nil {
		t.Fatal("verify accepted a wrong passphrase")
	}
}

func TestProtectedIdentity(t *testing.T) {
	dir := t.TempDir()
	passfile := write(t, filepath.Join(dir, "idpass"), []byte("key shield\n"))
	key := filepath.Join(dir, "locked.key")
	mustRun(t, cmdKeygen, "-o", key, "-passfile", passfile)

	raw, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("SINDOOK")) {
		t.Fatal("protected identity is not sealed")
	}
	if bytes.Contains(raw, []byte(skPrefix)) {
		t.Fatal("secret key visible in protected identity")
	}
	// The sealed identity opens with the passphrase and parses.
	dec, err := openSealedIdentity(raw, []byte("key shield"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseIdentity(dec, key)
	if err != nil {
		t.Fatal(err)
	}
	// Its plaintext .pub matches the sealed private key.
	pubLine, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := loadRecipient(strings.TrimSpace(string(pubLine)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, id.PublicKey()) {
		t.Fatal("pub file does not match sealed identity")
	}

	// The protected identity is usable non-interactively for automation and
	// with flags placed after a file operand.
	in := write(t, filepath.Join(dir, "protected.txt"), []byte("scheduled backup"))
	mustRun(t, cmdSeal, "-r", key+".pub", in)
	mustRun(t, cmdVerify, in+ext, "-i", key, "-identity-passfile", passfile)
	mustRun(t, cmdPubkey, key, "-identity-passfile", passfile)
}

func TestManagedContactsAndDefaultIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(dir, "config"))
	owner, ownerPub := newIdentity(t, dir, "owner.key")
	alice, alicePub := newIdentity(t, dir, "alice.key")

	// init records an explicit path and makes it the automatic default:
	// bare credential-less commands load it, and -i @default stays portable.
	mustRun(t, cmdInit, "-i", owner)
	bareID, _, err := loadCredentials("", false, "", "", "passphrase")
	if err != nil {
		t.Fatalf("bare credentials did not load the default identity: %v", err)
	}
	if bareID == nil {
		t.Fatal("bare credentials returned no identity")
	}
	bareID.Wipe()

	plain := write(t, filepath.Join(dir, "owner.txt"), []byte("default identity flow"))
	mustRun(t, cmdSeal, plain, "-r", ownerPub)
	mustRun(t, cmdVerify, plain+ext, "-i", "@default")

	mustRun(t, cmdContacts, "add", "Alice", alicePub)
	teamPlain := write(t, filepath.Join(dir, "team.txt"), []byte("named contact flow"))
	mustRun(t, cmdSeal, "-r", "@ALICE", teamPlain)
	mustRun(t, cmdVerify, "-i", alice, teamPlain+ext)

	cfg, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultIdentity != owner {
		t.Fatalf("default identity = %q, want %q", cfg.DefaultIdentity, owner)
	}
	if _, ok := cfg.Contacts["alice"]; !ok {
		t.Fatalf("saved contacts = %#v, want alice", cfg.Contacts)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(skPrefix)) || !bytes.Contains(raw, []byte(pkPrefix)) {
		t.Fatalf("managed config must contain public metadata only:\n%s", raw)
	}
}

func TestPortableGlobAndFlagsAfterOperands(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	first := write(t, filepath.Join(dir, "first.batch"), []byte("first"))
	second := write(t, filepath.Join(dir, "second.batch"), []byte("second"))

	// -glob is expanded by Sindook itself, so Windows cmd.exe and POSIX shells
	// have identical batch behavior. Flags after files are accepted too.
	mustRun(t, cmdSeal, "-r", pub, "-glob", filepath.Join(dir, "*.batch"))
	mustRun(t, cmdVerify, first+ext, "-i", key)
	mustRun(t, cmdVerify, "-i", key, "-glob", filepath.Join(dir, "*.batch"+ext))

	out := filepath.Join(dir, "opened.txt")
	mustRun(t, cmdOpen, first+ext, "-i", key, "-o", out)
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "first" {
		t.Fatalf("opened output = %q, %v", got, err)
	}
	if _, err := os.Stat(second + ext); err != nil {
		t.Fatalf("glob did not seal %s: %v", second, err)
	}
}

func TestKeygenPreflightPreventsOrphanPrivateIdentity(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	write(t, key+".pub", []byte("existing public key"))
	if err := cmdKeygen([]string{"-o", key}); err == nil {
		t.Fatal("keygen unexpectedly replaced an existing public key")
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed keygen left private identity behind: %v", err)
	}
}

func TestRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	aliceKey, alicePub := newIdentity(t, dir, "alice.key")
	bobKey, bobPub := newIdentity(t, dir, "bob.key")
	a, _ := os.ReadFile(alicePub)
	b, _ := os.ReadFile(bobPub)
	team := write(t, filepath.Join(dir, "team.keys"),
		[]byte("# the team\n\n"+string(a)+string(b)))

	in := write(t, filepath.Join(dir, "memo.txt"), []byte("for the team"))
	mustRun(t, cmdSeal, "-R", team, in)
	mustRun(t, cmdVerify, "-i", aliceKey, in+ext)
	mustRun(t, cmdVerify, "-i", bobKey, in+ext)
}

func TestRewrapRotation(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	newKey, newPub := newIdentity(t, dir, "new.key")
	in := write(t, filepath.Join(dir, "vault.txt"), []byte("rotate me"))

	mustRun(t, cmdSeal, "-r", oldPub, in)
	sealed := in + ext

	// Fast rotation in place: new identity gains access.
	mustRun(t, cmdRewrap, "-i", oldKey, "-r", newPub, "-r", oldPub, sealed)
	mustRun(t, cmdVerify, "-i", newKey, sealed)

	// Deep rotation drops the old identity entirely.
	mustRun(t, cmdRewrap, "-i", oldKey, "-r", newPub, "-deep", sealed)
	mustRun(t, cmdVerify, "-i", newKey, sealed)
	if err := cmdVerify([]string{"-i", oldKey, sealed}); err == nil {
		t.Fatal("revoked identity still opens after deep rewrap")
	}
}

func TestRewrapArmoredStaysArmored(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	newKey, newPub := newIdentity(t, dir, "new.key")
	in := write(t, filepath.Join(dir, "msg.txt"), []byte("armored rotation"))

	mustRun(t, cmdSeal, "-r", oldPub, "-a", in)
	sealed := in + ext
	mustRun(t, cmdRewrap, "-i", oldKey, "-r", newPub, sealed)

	raw, _ := os.ReadFile(sealed)
	if !strings.HasPrefix(string(raw), "-----BEGIN SINDOOK ENCRYPTED FILE-----") {
		t.Fatal("rewrap dropped the armor")
	}
	mustRun(t, cmdVerify, "-i", newKey, sealed)
}

func TestInspectJSON(t *testing.T) {
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")
	passfile := write(t, filepath.Join(dir, "pass"), []byte("inspect pw\n"))
	in := write(t, filepath.Join(dir, "doc.txt"), []byte("inspect me"))
	mustRun(t, cmdSeal, "-r", pub, "-passfile", passfile, in)

	rep, err := inspectOne(in + ext)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != 2 || len(rep.Slots) != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.PlaintextSize == nil || *rep.PlaintextSize != int64(len("inspect me")) {
		t.Fatalf("plaintext size wrong: %+v", rep.PlaintextSize)
	}
	if rep.Slots[1].Argon == nil {
		t.Fatalf("passphrase slot argon params missing: %+v", rep.Slots)
	}
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesUnknownSuffix(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "data.txt"), []byte("x"))
	out := filepath.Join(dir, "sealed.bin")
	mustRun(t, cmdSeal, "-r", pub, "-o", out, in)
	if err := cmdOpen([]string{"-i", key, out}); err == nil || !strings.Contains(err.Error(), ext) {
		t.Fatalf("want suffix error, got %v", err)
	}
}

func TestNoClobberWithoutForce(t *testing.T) {
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "data.txt"), []byte("x"))
	write(t, in+ext, []byte("existing"))
	if err := cmdSeal([]string{"-r", pub, in}); err == nil {
		t.Fatal("seal clobbered an existing file without -f")
	}
	if got, _ := os.ReadFile(in + ext); string(got) != "existing" {
		t.Fatal("existing file was damaged")
	}
}

func TestVerifyCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	in := write(t, filepath.Join(dir, "data.txt"), bytes.Repeat([]byte("y"), 1000))
	mustRun(t, cmdSeal, "-r", pub, in)

	raw, _ := os.ReadFile(in + ext)
	raw[len(raw)-10] ^= 0x01
	write(t, in+ext, raw)
	if err := cmdVerify([]string{"-i", key, in + ext}); err == nil {
		t.Fatal("verify passed a corrupted file")
	}
}

// TestBinaryHelp exercises the built binary itself: global help, command
// help, version, the unknown-command path, and the scriptable exit codes
// with their behaviors.
//
// Robustness notes (regression for ubuntu OOM with memguard mlockall):
//   - The test must NOT be run with t.Parallel(): it builds a binary and
//     fixtures on the local filesystem. The suite already isolates
//     SINDOOK_CONFIG_DIR via t.Setenv; this test also forces an isolated
//     config directory for all child processes so host state cannot leak.
//   - go build and each binary invocation are wrapped in context timeouts
//     to survive slow /tmp on CI.
//   - The build has a single retry with backoff for transient filesystem
//     races.
//   - Passfiles are created with 0600 and are wiped/removed after use to
//     avoid leaving secrets on disk longer than needed. t.TempDir already
//     guarantees cleanup, but explicit wipe reduces exposure window.
//   - Fixture sealing and each exit-code assertion use CommandContext so a
//     hung binary (e.g. regressed memguard MCL_FUTURE OOM) cannot hang the
//     whole suite indefinitely.
func TestBinaryHelp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	// Isolate child-process configuration. t.Setenv gives per-test isolation
	// for the current process; we also make the directory explicit so the
	// built binary observes the same isolated root.
	isolatedConfig := filepath.Join(t.TempDir(), "sindook-config")
	if err := os.MkdirAll(isolatedConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SINDOOK_CONFIG_DIR", isolatedConfig)

	binDir := t.TempDir()
	bin := filepath.Join(binDir, "sindook")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Build the binary with timeout + one retry for flaky /tmp.
	var buildOut []byte
	var buildErr error
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
		cmd.Env = os.Environ()
		buildOut, buildErr = cmd.CombinedOutput()
		cancel()
		if buildErr == nil {
			break
		}
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("go build timed out (attempt %d): %v\n%s", attempt, buildErr, buildOut)
		}
		if attempt == 2 {
			t.Fatalf("build: %v\n%s", buildErr, buildOut)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("binary not present after build: %v\n%s", err, buildOut)
	}

	// Exit-code fixtures: a passphrase-sealed file and a wrong passfile.
	dir := t.TempDir()
	plain := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(plain, []byte("exit code fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	passfile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passfile, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(passfile); err == nil && fi.Mode().Perm() != 0o600 {
			t.Fatalf("passfile mode = %#o, want 0600", fi.Mode().Perm())
		}
	}
	// Wipe passfile before TempDir cleanup to reduce secret lifetime.
	defer func() {
		_ = os.WriteFile(passfile, bytes.Repeat([]byte{0}, 32), 0o600)
		_ = os.Remove(passfile)
	}()
	wrong := filepath.Join(dir, "wrong")
	if err := os.WriteFile(wrong, []byte("battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(wrong); err == nil && fi.Mode().Perm() != 0o600 {
			t.Fatalf("wrong passfile mode = %#o, want 0600", fi.Mode().Perm())
		}
	}
	defer func() {
		_ = os.WriteFile(wrong, bytes.Repeat([]byte{0}, 32), 0o600)
		_ = os.Remove(wrong)
	}()

	// Use isolated env for all subprocesses; inherit parent env (already
	// contains the isolated SINDOOK_CONFIG_DIR from t.Setenv).
	env := os.Environ()
	// Seal the fixture via the binary with a timeout so a memguard OOM
	// regression (previously triggered on ubuntu with low RLIMIT_MEMLOCK)
	// fails fast instead of hanging.
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "seal", "-passfile", passfile, plain)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("fixture seal timed out (possible memguard OOM): %v\n%s", err, out)
			}
			t.Fatalf("fixture seal: %v\n%s", err, out)
		}
	}()
	sealed := plain + ext
	if _, err := os.Stat(sealed); err != nil {
		t.Fatalf("sealed fixture not created: %v", err)
	}

	for _, tc := range []struct {
		args     []string
		exitCode int
		want     string
	}{
		{[]string{"help"}, 0, "usage: sindook <command>"},
		{[]string{"help", "seal"}, 0, "usage: sindook seal"},
		{[]string{"seal", "-h"}, 0, "usage: sindook seal"},
		{[]string{"version"}, 0, "sindook " + version},
		{[]string{"help", "doctor"}, 0, "usage: sindook doctor"},
		{[]string{"help", "shred"}, 0, "usage: sindook shred"},
		{[]string{"selftest"}, 0, "box tamper detection: ok"},
		{[]string{"frobnicate"}, 2, "unknown command"},
		{[]string{"completion", "bash"}, 0, "_sindook"},
		{[]string{"completion", "powershell"}, 0, "Register-ArgumentCompleter"},
		{[]string{"completion", "tcsh"}, 2, "unknown shell"},
		{[]string{"seal"}, 2, "provide at least one"},
		{[]string{"open", "-passfile", wrong, "-o", filepath.Join(dir, "out.txt"), sealed}, 3, "cannot unwrap file key"},
		{[]string{"open", "-passfile", wrong, filepath.Join(dir, "missing.sindook")}, 1, ""},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, bin, tc.args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		cancel()
		if ctx.Err() == context.DeadlineExceeded {
			t.Errorf("%v: timed out after 15s (binary hung)\n%s", tc.args, out)
			continue
		}
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if code != tc.exitCode {
			t.Errorf("%v: exit %d, want %d\n%s", tc.args, code, tc.exitCode, out)
		}
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("%v: output missing %q:\n%s", tc.args, tc.want, out)
		}
	}
}

// TestMemguardLowLimitStillSeals ensures that even after memguard.LockAll
// the process can still seal with the production Argon2id parameters
// (64 MiB). This directly guards against the ubuntu CI OOM where
// LockAll with MCL_FUTURE under a low RLIMIT_MEMLOCK caused the next
// 64 MiB argon2 allocation to fault as VM_LOCKED and abort the runtime.
func TestMemguardLowLimitStillSeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy argon2 in -short mode")
	}
	if err := memguard.LockAll(); err != nil {
		t.Logf("memguard.LockAll: %v (continuing to verify sealing still works)", err)
	}
	t.Logf("memguard status: %s", memguard.Status())

	pass := []byte("correct horse battery staple")
	plain := []byte("low-limit payload for memguard regression")
	var sealed bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- box.SealPassphrase(&sealed, bytes.NewReader(plain), pass, box.DefaultArgon2id)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SealPassphrase after LockAll failed: %v (regression: locking should not cause OOM)", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("SealPassphrase after LockAll timed out (possible memguard OOM/deadlock)")
	}

	var out bytes.Buffer
	if err := box.Open(&out, bytes.NewReader(sealed.Bytes()), nil, pass); err != nil {
		t.Fatalf("Open after LockAll failed: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("round-trip mismatch after LockAll: got %q want %q", out.Bytes(), plain)
	}
}

// TestExitCodeDoesNotMisclassifyOOM verifies that the exitCode mapper does
// not treat a fatal OOM/panic-like error as a usage error (exit 2). OOM
// from memguard/argon2 must surface as operational failure (exit 1), not as
// a misleading "usage" diagnostic.
func TestExitCodeDoesNotMisclassifyOOM(t *testing.T) {
	// Simulate an OOM-like plain error (as the runtime would for a failed
	// large allocation) and a wrapped version. Neither should be mistaken
	// for ErrWrongKey / ErrNeed* (exit 3) nor for usageError (exit 2).
	oom := errors.New("fatal error: runtime: out of memory: cannot allocate 67108864-byte block")
	if got := exitCode(oom); got != 1 {
		t.Fatalf("exitCode(OOM) = %d, want 1 (operational)", got)
	}
	wrapped := errors.Join(oom, box.ErrWrongKey)
	// Auth error present, but OOM is also present; usage still beats auth,
	// but plain OOM+auth without usage should be auth (3). Ensure we don't
	// accidentally map OOM to usage.
	if got := exitCode(wrapped); got != 3 {
		t.Fatalf("exitCode(OOM + auth) = %d, want 3", got)
	}
	joinedUsage := errors.Join(oom, usagef("bad flag"))
	if got := exitCode(joinedUsage); got != 2 {
		t.Fatalf("exitCode(OOM + usage) = %d, want 2", got)
	}
}

// TestBinaryProductFlow keeps the product layer black-box: the compiled
// executable creates an explicit default identity, resolves a named contact,
// accepts flags after an operand, and uses an isolated portable config root.
// It runs unchanged on the Linux, macOS, and Windows CI jobs.
func TestBinaryProductFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary product flow in -short mode")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sindook")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	configDir := filepath.Join(dir, "config")
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SINDOOK_CONFIG_DIR=") {
			env = append(env, entry)
		}
	}
	env = append(env, "SINDOOK_CONFIG_DIR="+configDir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sindook %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init", "-o", "owner.key")
	run("keygen", "-o", "alice.key")
	run("contacts", "add", "alice", "alice.key.pub")
	write(t, filepath.Join(dir, "report.txt"), []byte("black-box product flow"))
	run("seal", "report.txt", "-r", "@default")
	run("verify", "report.txt.sindook", "-i", "@default")
	run("seal", "report.txt", "-r", "@alice", "-o", "for-alice.sindook")
	run("verify", "for-alice.sindook", "-i", "alice.key")
	run("doctor", "-json")
}
