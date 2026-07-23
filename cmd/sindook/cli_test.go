package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
// help, version, and the unknown-command path with their exit codes.
func TestBinaryHelp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "sindook")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
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
		{[]string{"frobnicate"}, 2, "unknown command"},
		{[]string{"completion", "bash"}, 0, "_sindook"},
		{[]string{"completion", "powershell"}, 1, "unknown shell"},
	} {
		out, err := exec.Command(bin, tc.args...).CombinedOutput()
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
