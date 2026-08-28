package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateConfig points SINDOOK_CONFIG_DIR at a fresh directory so tests
// never read or write the developer's real contacts and groups.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config")
	t.Setenv("SINDOOK_CONFIG_DIR", dir)
	return dir
}

func addContactIdentity(t *testing.T, dir, name string) string {
	t.Helper()
	_, pub := newIdentity(t, dir, name+".key")
	mustRun(t, cmdContacts, "add", name, pub)
	return pub
}

func TestGroupSealFlow(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	addContactIdentity(t, dir, "alice")
	bobKey := filepath.Join(dir, "bob.key")
	mustRun(t, cmdKeygen, "-o", bobKey)
	mustRun(t, cmdContacts, "add", "bob", bobKey+".pub")
	carolKey := filepath.Join(dir, "carol.key")
	mustRun(t, cmdKeygen, "-o", carolKey)
	mustRun(t, cmdContacts, "add", "carol", carolKey+".pub")

	mustRun(t, cmdContacts, "group", "add", "team", "alice", "bob")

	in := write(t, filepath.Join(dir, "plan.txt"), []byte("group secret"))
	mustRun(t, cmdSeal, "-r", "@team", in)

	mustRun(t, cmdVerify, "-i", filepath.Join(dir, "alice.key"), in+ext)
	mustRun(t, cmdVerify, "-i", bobKey, in+ext)
	if err := cmdVerify([]string{"-i", carolKey, in + ext}); err == nil {
		t.Fatal("non-member opened a group-sealed file")
	}

	out, err := captureStdout(t, func() error {
		return cmdInspect([]string{"-json", in + ext})
	})
	if err != nil {
		t.Fatal(err)
	}
	var reports []inspectReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("inspect -json: %v", err)
	}
	if len(reports) != 1 || len(reports[0].Slots) != 2 {
		t.Fatalf("group seal produced %d reports with %v slots", len(reports), reports)
	}

	groups, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "list", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var reportsGroups []groupReport
	if err := json.Unmarshal([]byte(groups), &reportsGroups); err != nil {
		t.Fatalf("group list -json: %v", err)
	}
	if len(reportsGroups) != 1 || reportsGroups[0].Name != "team" ||
		strings.Join(reportsGroups[0].Members, ",") != "alice,bob" {
		t.Fatalf("group list -json = %+v", reportsGroups)
	}

	show, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "show", "team"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if show != "alice\nbob\n" {
		t.Fatalf("group show = %q", show)
	}
}

func TestGroupMembershipEdits(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	addContactIdentity(t, dir, "alice")
	addContactIdentity(t, dir, "bob")
	addContactIdentity(t, dir, "carol")

	mustRun(t, cmdContacts, "group", "add", "team", "alice")
	mustRun(t, cmdContacts, "group", "add-member", "team", "bob", "carol")

	in := write(t, filepath.Join(dir, "doc.txt"), []byte("secret"))
	mustRun(t, cmdSeal, "-r", "@team", in)
	out, err := captureStdout(t, func() error {
		return cmdInspect([]string{"-json", in + ext})
	})
	if err != nil {
		t.Fatal(err)
	}
	var reports []inspectReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Slots) != 3 {
		t.Fatalf("expected 3 slots after add-member, got %d", len(reports[0].Slots))
	}

	mustRun(t, cmdContacts, "group", "remove-member", "team", "bob")
	if _, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "remove-member", "team", "bob"})
	}); err == nil || !strings.Contains(err.Error(), "no member @bob") {
		t.Fatalf("removing absent member: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return cmdContactsGroupEdit([]string{"team", "alice", "carol"}, false)
	}); err == nil || !strings.Contains(err.Error(), "at least one member") {
		t.Fatalf("emptying a group: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "add-member", "ghost", "alice"})
	}); err == nil || !strings.Contains(err.Error(), "unknown group @ghost") {
		t.Fatalf("editing unknown group: %v", err)
	}

	mustRun(t, cmdContacts, "group", "remove", "team")
	if _, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "show", "team"})
	}); err == nil || !strings.Contains(err.Error(), "unknown group @team") {
		t.Fatalf("show removed group: %v", err)
	}
}

func TestGroupNamespaceGuards(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	alicePub := addContactIdentity(t, dir, "alice")
	addContactIdentity(t, dir, "bob")

	if _, err := captureStdout(t, func() error {
		return cmdContactsGroupAdd([]string{"alice", "bob"})
	}); err == nil || !strings.Contains(err.Error(), "@alice is a saved contact") {
		t.Fatalf("group over contact: %v", err)
	}

	mustRun(t, cmdContacts, "group", "add", "team", "alice", "bob")
	if _, err := captureStdout(t, func() error {
		return cmdContactsAdd([]string{"-f", "team", alicePub})
	}); err == nil || !strings.Contains(err.Error(), "@team is a saved group") {
		t.Fatalf("contact over group: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return cmdContactsRemove([]string{"alice"})
	}); err == nil || !strings.Contains(err.Error(), "member of @team") {
		t.Fatalf("removing grouped contact: %v", err)
	}

	mustRun(t, cmdContacts, "group", "remove", "team")
	mustRun(t, cmdContacts, "remove", "alice")
}

func TestGroupDeduplicatesKeys(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "shared.key")
	mustRun(t, cmdContacts, "add", "alice", pub)
	mustRun(t, cmdContacts, "add", "bob", pub)
	mustRun(t, cmdContacts, "group", "add", "team", "alice", "bob")

	in := write(t, filepath.Join(dir, "note.txt"), []byte("dedup"))
	mustRun(t, cmdSeal, "-r", "@team", in)
	out, err := captureStdout(t, func() error {
		return cmdInspect([]string{"-json", in + ext})
	})
	if err != nil {
		t.Fatal(err)
	}
	var reports []inspectReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Slots) != 1 {
		t.Fatalf("duplicate group keys produced %d slots, want 1", len(reports[0].Slots))
	}
}

func TestGroupUnknownMemberFailsClosed(t *testing.T) {
	cfgDir := isolateConfig(t)
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")
	mustRun(t, cmdContacts, "add", "alice", pub)

	if _, err := captureStdout(t, func() error {
		return cmdContactsGroupAdd([]string{"team", "alice", "ghost"})
	}); err == nil || !strings.Contains(err.Error(), "@ghost is not a saved contact") {
		t.Fatalf("group add with unknown member: %v", err)
	}

	cfgPath := filepath.Join(cfgDir, "config.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw),
		`"contacts"`, `"groups": {"team": {"members": ["alice", "ghost"], "added_at": "2026-01-01T00:00:00Z"}}, "contacts"`, 1)
	write(t, cfgPath, []byte(tampered))

	in := write(t, filepath.Join(dir, "doc.txt"), []byte("secret"))
	if _, err := captureStdout(t, func() error {
		return cmdSeal([]string{"-r", "@team", in})
	}); err == nil || !strings.Contains(err.Error(), "@ghost is not a saved contact") {
		t.Fatalf("seal with dangling group member: %v", err)
	}
}

func TestGroupConfigWithoutGroupsKey(t *testing.T) {
	cfgDir := isolateConfig(t)
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")
	mustRun(t, cmdContacts, "add", "alice", pub)

	cfgPath := filepath.Join(cfgDir, "config.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// A config written before groups existed (or containing only contacts)
	// carries no groups key at all and must keep loading.
	if strings.Contains(string(raw), "groups") {
		t.Fatalf("fresh single-contact config should carry no groups key:\n%s", raw)
	}

	out, err := captureStdout(t, func() error {
		return cmdContactsList([]string{"-json"})
	})
	if err != nil {
		t.Fatalf("old config without groups key failed: %v", err)
	}
	var contacts []contactReport
	if err := json.Unmarshal([]byte(out), &contacts); err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 || contacts[0].Name != "alice" {
		t.Fatalf("contacts from old config = %+v", contacts)
	}

	_, pub2 := newIdentity(t, dir, "second.key")
	mustRun(t, cmdContacts, "add", "bob", pub2)
	mustRun(t, cmdContacts, "group", "add", "team", "alice", "bob")

	groups, err := captureStdout(t, func() error {
		return cmdContacts([]string{"group", "list", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var reports []groupReport
	if err := json.Unmarshal([]byte(groups), &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].Members) != 2 {
		t.Fatalf("groups after upgrade = %+v", reports)
	}
}

func TestConfigCommand(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdKeygen, "-o", key)

	if _, err := captureStdout(t, func() error {
		return cmdConfigGet([]string{"default-identity"})
	}); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("get unset key: %v", err)
	}

	mustRun(t, cmdConfig, "set", "default-identity", key)
	got, err := captureStdout(t, func() error {
		return cmdConfigGet([]string{"default-identity"})
	})
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(key)
	if strings.TrimSpace(got) != abs {
		t.Fatalf("config get = %q, want %q", got, abs)
	}

	out, err := captureStdout(t, func() error {
		return cmdConfig([]string{"list", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var report configReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if !report.DefaultIdentitySet || report.DefaultIdentity != abs {
		t.Fatalf("config list -json = %+v", report)
	}

	mustRun(t, cmdConfig, "unset", "default-identity")
	if _, err := captureStdout(t, func() error {
		return cmdConfigGet([]string{"default-identity"})
	}); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("get after unset: %v", err)
	}
	if _, err := captureStdout(t, func() error {
		return cmdConfigUnset([]string{"default-identity"})
	}); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("unset twice: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return cmdConfigSet([]string{"default-identity", filepath.Join(dir, "missing.key")})
	}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("set nonexistent identity: %v", err)
	}
	for _, bad := range [][]string{
		{"get", "bogus"},
		{"set", "bogus", "x"},
		{"unset", "bogus"},
		{"bogus"},
	} {
		if _, err := captureStdout(t, func() error {
			return cmdConfig(bad)
		}); err == nil || exitCode(err) != 2 {
			t.Errorf("config %v: got %v, want usage error", bad, err)
		}
	}
}

func TestConfigDefaultIdentityDrivesOpen(t *testing.T) {
	isolateConfig(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "id.key")
	mustRun(t, cmdKeygen, "-o", key)

	mustRun(t, cmdConfig, "set", "default-identity", key)
	in := write(t, filepath.Join(dir, "note.txt"), []byte("default identity"))
	mustRun(t, cmdSeal, "-r", key+".pub", in)
	mustRun(t, cmdOpen, "-o", filepath.Join(dir, "note.out"), in+ext)
	got, err := os.ReadFile(filepath.Join(dir, "note.out"))
	if err != nil || string(got) != "default identity" {
		t.Fatalf("open with configured default identity: %q %v", got, err)
	}
}
