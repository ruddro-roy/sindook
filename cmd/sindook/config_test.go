package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/ruddro-roy/sindook/xwing"
)

// captureStdout redirects os.Stdout to a temp file while fn runs and returns
// everything written. Passphrase prompts still go to stderr/the terminal, so
// tests that capture stdout must use -passfile or credential-less commands.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "stdout-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = tmp
	defer func() { os.Stdout = old }()
	runErr := fn()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), runErr
}

// configEnv points the managed configuration at a fresh isolated directory.
func configEnv(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	t.Setenv("SINDOOK_CONFIG_DIR", dir)
	return dir
}

func TestConfigDirOverridePathsJSON(t *testing.T) {
	dir := configEnv(t)
	out, err := captureStdout(t, func() error { return cmdPaths([]string{"-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var rep pathsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("paths -json output: %v\n%s", err, out)
	}
	if rep.ConfigDirectory != dir {
		t.Errorf("config_directory = %q, want %q", rep.ConfigDirectory, dir)
	}
	if want := filepath.Join(dir, "config.json"); rep.ConfigFile != want {
		t.Errorf("config_file = %q, want %q", rep.ConfigFile, want)
	}
	if rep.DefaultIdentity != "" || rep.DefaultIdentityReady || rep.Contacts != 0 {
		t.Errorf("fresh configuration should be empty, got %+v", rep)
	}
}

func TestInitCreatesIdentityAndSetsDefault(t *testing.T) {
	configDir := configEnv(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdInit, "-o", key)

	for path, want := range map[string]os.FileMode{key: 0o600, key + ".pub": 0o644} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !info.Mode().IsRegular() {
			t.Errorf("%s is not a regular file", path)
		}
		if runtime.GOOS != "windows" {
			if got := info.Mode().Perm(); got != want {
				t.Errorf("%s mode = %#o, want %#o", path, got, want)
			}
		}
	}

	out, err := captureStdout(t, func() error { return cmdPaths([]string{"-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var rep pathsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.DefaultIdentity != key || !rep.DefaultIdentityReady {
		t.Errorf("default identity = %q ready=%v, want %q ready=true", rep.DefaultIdentity, rep.DefaultIdentityReady, key)
	}

	if runtime.GOOS != "windows" {
		di, err := os.Stat(configDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := di.Mode().Perm(); got != 0o700 {
			t.Errorf("config dir mode = %#o, want 0700", got)
		}
		fi, err := os.Stat(filepath.Join(configDir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("config file mode = %#o, want 0600", got)
		}
	}
}

func TestInitSelectsExistingIdentity(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	key, _ := newIdentity(t, dir, "existing.key")
	mustRun(t, cmdInit, "-i", key)
	cfg, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultIdentity != key {
		t.Errorf("default identity = %q, want %q", cfg.DefaultIdentity, key)
	}
}

func TestInitOverwriteExisting(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	write(t, key, []byte("existing identity contents"))
	if err := cmdInit([]string{"-o", key}); err == nil {
		t.Fatal("init overwrote an existing identity without -f")
	}
	got, err := os.ReadFile(key)
	if err != nil || string(got) != "existing identity contents" {
		t.Fatalf("failed init damaged the existing identity: %q, %v", got, err)
	}
	if _, err := defaultIdentityPath(); err == nil {
		t.Fatal("failed init left a default identity behind")
	}

	mustRun(t, cmdInit, "-o", key, "-f")
	if _, err := loadIdentityWithPassfile(key, ""); err != nil {
		t.Fatalf("forced init identity does not parse: %v", err)
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultIdentity != key {
		t.Errorf("default identity = %q, want %q", cfg.DefaultIdentity, key)
	}
}

func TestInitPromptWithoutTerminalFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("console prompt behavior differs on Windows")
	}
	configEnv(t)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal; the passphrase prompt would block")
	}
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Skip("a controlling terminal is available; the passphrase prompt would block")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	err := cmdInit([]string{"-o", key, "-p"})
	if err == nil {
		t.Fatal("init -p succeeded without a terminal")
	}
	if !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("error = %v, want a no-terminal diagnostic", err)
	}
	if _, statErr := os.Stat(key); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed init -p left an identity behind: %v", statErr)
	}
	if _, statErr := os.Stat(key + ".pub"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed init -p left a public key behind: %v", statErr)
	}
}

func TestInitPassfileProtectedIdentity(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	passfile := write(t, filepath.Join(dir, "pass"), []byte("shield pw\n"))
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdInit, "-o", key, "-passfile", passfile)

	raw, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("SINDOOK")) {
		t.Fatal("identity was not sealed with the passphrase")
	}
	id, err := loadIdentityWithPassfile(key, passfile)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := loadRecipient(strings.TrimSpace(string(pubRaw)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, id.PublicKey()) {
		t.Fatal("public key file does not match the passphrase-protected identity")
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultIdentity != key {
		t.Errorf("default identity = %q, want %q", cfg.DefaultIdentity, key)
	}
}

func TestPathsMissingDefaultIdentity(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "gone.key")
	if err := setDefaultIdentity(key); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return cmdPaths([]string{"-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var rep pathsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.DefaultIdentity != key || rep.DefaultIdentityReady {
		t.Errorf("default identity = %q ready=%v, want %q ready=false", rep.DefaultIdentity, rep.DefaultIdentityReady, key)
	}
	if _, err := defaultPublicKeyPath(); err == nil {
		t.Fatal("default public key resolved for a missing identity")
	}
}

func TestContactsAddFromFileLiteralAndInvalidNames(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	_, pubPath := newIdentity(t, dir, "alice.key")
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	literal := strings.TrimSpace(string(pubRaw))
	pub, err := loadRecipient(literal)
	if err != nil {
		t.Fatal(err)
	}

	mustRun(t, cmdContacts, "add", "alice", pubPath)
	mustRun(t, cmdContacts, "add", "bob", literal)

	cfg, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := canonicalPublicKey(pub)
	for _, name := range []string{"alice", "bob"} {
		contact, ok := cfg.Contacts[name]
		if !ok {
			t.Fatalf("contact @%s not saved: %#v", name, cfg.Contacts)
		}
		if contact.PublicKey != want {
			t.Errorf("contact @%s public key = %q, want %q", name, contact.PublicKey, want)
		}
		if _, err := time.Parse(time.RFC3339, contact.AddedAt); err != nil {
			t.Errorf("contact @%s added_at = %q is not RFC3339: %v", name, contact.AddedAt, err)
		}
	}

	if err := cmdContacts([]string{"add", "alice", pubPath}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate add error = %v, want already-exists error", err)
	}
	_, otherPubPath := newIdentity(t, dir, "other.key")
	mustRun(t, cmdContacts, "add", "alice", "-f", otherPubPath)
	otherRaw, err := os.ReadFile(otherPubPath)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := loadRecipient(strings.TrimSpace(string(otherRaw)))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Contacts["alice"].PublicKey != canonicalPublicKey(otherPub) {
		t.Error("forced add did not replace the saved key")
	}

	for _, name := range []string{"bad name!", "CON", strings.Repeat("a", 65)} {
		if err := cmdContacts([]string{"add", name, pubPath}); err == nil {
			t.Errorf("contacts add accepted invalid name %q", name)
		}
	}
	// A leading dash is a flag to the parser, so a literal "-lead" name must
	// arrive after "--"; it then fails name validation instead of flag parsing.
	if err := cmdContacts([]string{"add", "--", "-lead", pubPath}); err == nil {
		t.Error("contacts add accepted invalid name \"-lead\"")
	}
	cfg, err = loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Contacts) != 2 {
		t.Errorf("invalid names were saved: %#v", cfg.Contacts)
	}
}

func TestContactsListShowRemove(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	_, pubPath := newIdentity(t, dir, "alice.key")
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	literal := strings.TrimSpace(string(pubRaw))
	pub, err := loadRecipient(literal)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, cmdContacts, "add", "Alice", pubPath)

	out, err := captureStdout(t, func() error { return cmdContacts([]string{"list", "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var reports []contactReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("contacts list -json output: %v\n%s", err, out)
	}
	if len(reports) != 1 {
		t.Fatalf("contacts list -json = %+v, want one contact", reports)
	}
	if reports[0].Name != "alice" || reports[0].PublicKey != canonicalPublicKey(pub) {
		t.Errorf("contact report = %+v, want alice/%s", reports[0], canonicalPublicKey(pub))
	}

	out, err = captureStdout(t, func() error { return cmdContacts([]string{"list"}) })
	if err != nil {
		t.Fatal(err)
	}
	// Expected fingerprint computed independently of contactFingerprint, so
	// a regression in the function cannot also change the expectation.
	sum := sha256.Sum256(pub)
	fp := "sha256:" + hex.EncodeToString(sum[:16])
	if want := "@alice  " + fp; !strings.Contains(out, want) {
		t.Errorf("contacts list = %q, want it to contain %q", out, want)
	}
	if strings.Contains(out, pkPrefix) {
		t.Errorf("contacts list must not print the full public key: %q", out)
	}

	out, err = captureStdout(t, func() error { return cmdContacts([]string{"show", "ALICE"}) })
	if err != nil {
		t.Fatal(err)
	}
	if out != literal+"\n" {
		t.Errorf("contacts show = %q, want %q", out, literal+"\n")
	}

	mustRun(t, cmdContacts, "remove", "alice")
	if err := cmdContacts([]string{"remove", "alice"}); err == nil {
		t.Fatal("second remove succeeded")
	}
	out, err = captureStdout(t, func() error { return cmdContacts([]string{"list", "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var empty []contactReport
	if err := json.Unmarshal([]byte(out), &empty); err != nil || len(empty) != 0 {
		t.Errorf("contacts after remove = %s (%v), want empty array", out, err)
	}
}

func TestContactSealOpenRoundTrip(t *testing.T) {
	configEnv(t)
	dir := t.TempDir()
	owner := filepath.Join(dir, "owner.key")
	mustRun(t, cmdInit, "-o", owner)
	mustRun(t, cmdContacts, "add", "alice", owner+".pub")

	plain := []byte("contact round trip")
	in := write(t, filepath.Join(dir, "msg.txt"), plain)
	mustRun(t, cmdSeal, "-r", "@alice", in)
	out := filepath.Join(dir, "msg.out")
	mustRun(t, cmdOpen, "-i", owner, "-o", out, in+ext)
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("contact round trip mismatch: %q, %v", got, err)
	}

	defaultPlain := []byte("default round trip")
	in2 := write(t, filepath.Join(dir, "def.txt"), defaultPlain)
	mustRun(t, cmdSeal, "-r", "@default", in2)
	out2 := filepath.Join(dir, "def.out")
	mustRun(t, cmdOpen, "-i", "@default", "-o", out2, in2+ext)
	got2, err := os.ReadFile(out2)
	if err != nil || !bytes.Equal(got2, defaultPlain) {
		t.Fatalf("default round trip mismatch: %q, %v", got2, err)
	}
}

func TestLoadSindookConfigErrors(t *testing.T) {
	dir := configEnv(t)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, pubPath := newIdentity(t, t.TempDir(), "id.key")
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	validPK := strings.TrimSpace(string(pubRaw))

	for _, tc := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"unsupported version", `{"version": 99}`, "unsupported configuration version"},
		{"malformed json", `{"version":`, "parse configuration"},
		{"invalid saved name", `{"version":1,"contacts":{"bad name!":{"public_key":"` + validPK + `"}}}`, "invalid saved contact name"},
		{"non-normalized name", `{"version":1,"contacts":{"ALICE":{"public_key":"` + validPK + `"}}}`, "invalid saved contact name"},
		{"invalid saved key", `{"version":1,"contacts":{"alice":{"public_key":"garbage"}}}`, "invalid public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(t, cfgPath, []byte(tc.raw))
			_, err := loadSindookConfig()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("loadSindookConfig error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("valid config", func(t *testing.T) {
		write(t, cfgPath, []byte(`{"version":1,"default_identity":"/tmp/id.key","contacts":{"alice":{"public_key":"`+validPK+`","added_at":"2026-01-01T00:00:00Z"}}}`))
		cfg, err := loadSindookConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DefaultIdentity != "/tmp/id.key" {
			t.Errorf("default identity = %q", cfg.DefaultIdentity)
		}
		if _, ok := cfg.Contacts["alice"]; !ok {
			t.Errorf("contacts = %#v, want alice", cfg.Contacts)
		}
	})
}

func TestNormalizeContactName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"alice", "alice"},
		{"Alice", "alice"},
		{"@Bob", "bob"},
		{"a", "a"},
		{"1", "1"},
		{"123abc", "123abc"},
		{"a1b.c_d-e", "a1b.c_d-e"},
		{"UPPER.Case_Name-1", "upper.case_name-1"},
		{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"a..b", "a..b"},
		{"com0", "com0"},
		{"com10", "com10"},
		{"lpt0", "lpt0"},
	} {
		got, err := normalizeContactName(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalizeContactName(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}

	for _, name := range []string{
		"", " ", " alice", "alice ", "alice\t", "@",
		strings.Repeat("a", 65),
		".alice", "-lead", "_lead", "a$b", "bad name!",
		"con", "CON", "con.txt", "prn", "aux", "nul",
		"com1", "COM9", "lpt1", "LPT9", "clock$",
		"alice.", "aux.bak",
	} {
		if got, err := normalizeContactName(name); err == nil {
			t.Errorf("normalizeContactName(%q) = %q, want error", name, got)
		}
	}
}

func TestSaveSindookConfigPermissions(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "nested", "config")
	t.Setenv("SINDOOK_CONFIG_DIR", configDir)
	keyPath, _ := newIdentity(t, dir, "id.key")
	pubRaw, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}

	cfg := newSindookConfig()
	cfg.DefaultIdentity = keyPath
	cfg.Contacts["alice"] = savedContact{
		PublicKey: strings.TrimSpace(string(pubRaw)),
		AddedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveSindookConfig(cfg); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(configDir, "config.json")
	if runtime.GOOS != "windows" {
		di, err := os.Stat(configDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := di.Mode().Perm(); got != 0o700 {
			t.Errorf("config dir mode = %#o, want 0700", got)
		}
		fi, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("config file mode = %#o, want 0600", got)
		}
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Error("config.json is missing a trailing newline")
	}

	loaded, err := loadSindookConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DefaultIdentity != cfg.DefaultIdentity {
		t.Errorf("default identity = %q, want %q", loaded.DefaultIdentity, cfg.DefaultIdentity)
	}
	if got := loaded.Contacts["alice"].PublicKey; got != cfg.Contacts["alice"].PublicKey {
		t.Errorf("saved contact key = %q, want %q", got, cfg.Contacts["alice"].PublicKey)
	}
	if got := loaded.Contacts["alice"].AddedAt; got != cfg.Contacts["alice"].AddedAt {
		t.Errorf("saved contact added_at = %q, want %q", got, cfg.Contacts["alice"].AddedAt)
	}
}

// TestContactFingerprintFixedVector pins the fingerprint algorithm against
// an independently computed fixed value:
//
//	SHA-256 over the decoded 1216-byte X-Wing public key, first 16 bytes,
//	lowercase hex, prefixed "sha256:" (a 128-bit collision space).
//
// The literal below was computed from the deterministic identity with seed
// 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26 (the
// same seed as the box v1 golden fixtures), verified by hand with
// "printf 'PK' | openssl dgst -sha256" style tooling. The inline
// crypto/sha256.Sum256 call goes straight to the standard library and does
// not share code with contactFingerprint, so the test cannot validate a
// bug against itself.
func TestContactFingerprintFixedVector(t *testing.T) {
	const (
		seedHex          = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
		fingerprintFixed = "sha256:2e816deebcd76c5c80d0cd2d17447887"
	)
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := xwing.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()
	if len(pub) != 1216 {
		t.Fatalf("decoded public key length = %d, want 1216", len(pub))
	}
	sum := sha256.Sum256(pub)
	if got := "sha256:" + hex.EncodeToString(sum[:16]); got != fingerprintFixed {
		t.Fatalf("independently computed fingerprint = %q, fixed vector %q is stale", got, fingerprintFixed)
	}
	if got := contactFingerprint(pub); got != fingerprintFixed {
		t.Errorf("contactFingerprint = %q, want %q", got, fingerprintFixed)
	}
	if len(fingerprintFixed) != len("sha256:")+32 {
		t.Errorf("fingerprint length = %d hex chars, want 32 (128 bits)", len(fingerprintFixed)-len("sha256:"))
	}
}
