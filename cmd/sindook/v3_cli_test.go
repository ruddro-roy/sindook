package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/internal/box"
)

func inspectFile(t *testing.T, path string) inspectReport {
	t.Helper()
	rep, err := inspectOne(path)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestSealFormatSelection(t *testing.T) {
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")

	v3 := write(t, filepath.Join(dir, "a.txt"), []byte("default"))
	mustRun(t, cmdSeal, "-r", pub, v3)
	if got := inspectFile(t, v3+ext).Version; got != 3 {
		t.Fatalf("seal defaulted to format v%d, want v3", got)
	}

	v2 := write(t, filepath.Join(dir, "b.txt"), []byte("legacy"))
	mustRun(t, cmdSeal, "-r", pub, "-format", "2", v2)
	if got := inspectFile(t, v2+ext).Version; got != 2 {
		t.Fatalf("-format 2 produced v%d", got)
	}

	if err := cmdSeal([]string{"-r", pub, "-format", "4", v3}); err == nil {
		t.Fatal("an unknown format must be rejected")
	}
	if err := cmdSeal([]string{"-r", pub, "-format", "2", "-reserve", "8", v3}); err == nil {
		t.Fatal("arena flags must be rejected for format 2")
	}
}

func TestSealHeaderCapacityFlags(t *testing.T) {
	dir := t.TempDir()
	_, pub := newIdentity(t, dir, "id.key")

	tight := write(t, filepath.Join(dir, "tight.txt"), []byte("x"))
	mustRun(t, cmdSeal, "-r", pub, "-reserve", "0", tight)
	small := inspectFile(t, tight+ext).Arena.SlotCapacity

	roomy := write(t, filepath.Join(dir, "roomy.txt"), []byte("x"))
	mustRun(t, cmdSeal, "-r", pub, "-reserve", "16", roomy)
	large := inspectFile(t, roomy+ext).Arena.SlotCapacity

	if small >= large {
		t.Fatalf("-reserve 0 gave %d bytes, -reserve 16 gave %d: headroom is not being applied", small, large)
	}

	exact := write(t, filepath.Join(dir, "exact.txt"), []byte("x"))
	mustRun(t, cmdSeal, "-r", pub, "-header-capacity", "8192", exact)
	if got := inspectFile(t, exact+ext).Arena.SlotCapacity; got != 8192 {
		t.Fatalf("-header-capacity 8192 produced %d", got)
	}
	if err := cmdSeal([]string{"-r", pub, "-header-capacity", "5000", exact}); err == nil {
		t.Fatal("a capacity that is not a multiple of 4096 must be rejected")
	}
}

// TestStaffDepartureFlow is the workflow the format exists for: a colleague
// leaves, access is rotated across archives without re-encrypting them, and
// the result is auditable.
func TestStaffDepartureFlow(t *testing.T) {
	dir := t.TempDir()
	staysKey, staysPub := newIdentity(t, dir, "stays.key")
	leavesKey, leavesPub := newIdentity(t, dir, "leaves.key")

	plain := bytes.Repeat([]byte("retained archive "), 50_000)
	archive := write(t, filepath.Join(dir, "archive.tar"), plain)
	mustRun(t, cmdSeal, "-r", staysPub, "-r", leavesPub, archive)
	sealed := archive + ext

	before, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	payloadAt := inspectFile(t, sealed).Arena.PayloadOffset

	// One rotation removes the departing recipient.
	mustRun(t, cmdRewrap, "-i", staysKey, "-r", staysPub, sealed)

	after, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("rotation changed the file size from %d to %d", len(before), len(after))
	}
	if !bytes.Equal(before[payloadAt:], after[payloadAt:]) {
		t.Fatal("rotation rewrote payload ciphertext")
	}

	rep := inspectFile(t, sealed)
	if rep.Arena.Generation != 2 || !rep.Arena.Scrubbed {
		t.Fatalf("expected a scrubbed generation 2 arena, got generation %d scrubbed=%v",
			rep.Arena.Generation, rep.Arena.Scrubbed)
	}
	if len(rep.Slots) != 1 {
		t.Fatalf("expected one key slot after rotation, got %d", len(rep.Slots))
	}

	mustRun(t, cmdVerify, "-i", staysKey, sealed)
	if err := cmdVerify([]string{"-i", leavesKey, sealed}); err == nil {
		t.Fatal("the departed identity still opens the archive")
	}
	// And the payload is still exactly what was sealed.
	out := filepath.Join(dir, "restored.tar")
	mustRun(t, cmdOpen, "-i", staysKey, "-o", out, sealed)
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("restore drill failed: %v", err)
	}
}

func TestRewrapExpectGeneration(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	_, otherPub := newIdentity(t, dir, "other.key")
	in := write(t, filepath.Join(dir, "doc.txt"), []byte("policy"))
	mustRun(t, cmdSeal, "-r", pub, in)
	sealed := in + ext

	mustRun(t, cmdRewrap, "-i", key, "-r", pub, "-r", otherPub, "-expect-generation", "1", sealed)
	if err := cmdRewrap([]string{"-i", key, "-r", pub, "-expect-generation", "1", sealed}); err == nil {
		t.Fatal("a stale generation must be rejected")
	} else if !strings.Contains(err.Error(), "generation") {
		t.Fatalf("expected a generation error, got %v", err)
	}
	if got := inspectFile(t, sealed).Arena.Generation; got != 2 {
		t.Fatalf("the rejected rotation should not have advanced the generation, got %d", got)
	}
}

func TestMigrateCommand(t *testing.T) {
	dir := t.TempDir()
	key, pub := newIdentity(t, dir, "id.key")
	_, nextPub := newIdentity(t, dir, "next.key")
	plain := bytes.Repeat([]byte("legacy payload "), 10_000)
	in := write(t, filepath.Join(dir, "old.bin"), plain)

	mustRun(t, cmdSeal, "-r", pub, "-format", "2", in)
	sealed := in + ext

	// Migration needs the recipient list, and says so.
	if err := cmdMigrate([]string{"-i", key, sealed}); err == nil {
		t.Fatal("migrating a recipient file without -r must fail")
	}
	mustRun(t, cmdMigrate, "-i", key, "-r", pub, sealed)

	rep := inspectFile(t, sealed)
	if rep.Version != 3 || rep.Arena.Generation != 1 {
		t.Fatalf("migration produced v%d generation %d", rep.Version, rep.Arena.Generation)
	}
	out := filepath.Join(dir, "restored.bin")
	mustRun(t, cmdOpen, "-i", key, "-o", out, sealed)
	if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("migrated file does not restore: %v", err)
	}

	// Running it again is a no-op, not a second rewrite.
	fileBefore, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, cmdMigrate, "-i", key, "-r", pub, sealed)
	fileAfter, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileBefore, fileAfter) {
		t.Fatal("migrating an already-v3 file rewrote it")
	}

	// And the migrated file rotates in place.
	mustRun(t, cmdRewrap, "-i", key, "-r", nextPub, sealed)
	if got := inspectFile(t, sealed).Arena.Generation; got != 2 {
		t.Fatalf("rotation after migration left generation %d", got)
	}
}

func TestMigratePassphraseOnlyNeedsNoRecipients(t *testing.T) {
	dir := t.TempDir()
	passfile := write(t, filepath.Join(dir, "pass"), []byte("migrate pw\n"))
	plain := []byte("passphrase payload")
	in := write(t, filepath.Join(dir, "notes.txt"), plain)

	mustRun(t, cmdSeal, "-passfile", passfile, "-format", "2", in)
	sealed := in + ext
	mustRun(t, cmdMigrate, "-passfile", passfile, sealed)

	if got := inspectFile(t, sealed).Version; got != 3 {
		t.Fatalf("migration produced v%d", got)
	}
	out := filepath.Join(dir, "restored.txt")
	mustRun(t, cmdOpen, "-passfile", passfile, "-o", out, sealed)
	if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("migrated passphrase file does not restore: %v", err)
	}
}

func TestRepairAndRecoverCommands(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	newKey, newPub := newIdentity(t, dir, "new.key")
	plain := []byte("interrupted rotation payload")
	in := write(t, filepath.Join(dir, "doc.txt"), plain)
	mustRun(t, cmdSeal, "-r", oldPub, in)
	sealed := in + ext

	// Reproduce an interrupted rotation: write only the first header slot.
	interruptRotation(t, sealed, oldKey, newPub)

	rep := inspectFile(t, sealed)
	if rep.Arena.Scrubbed {
		t.Fatal("the arena should report itself unscrubbed")
	}

	// A normal open uses the new policy only.
	out := filepath.Join(dir, "out.txt")
	mustRun(t, cmdOpen, "-i", newKey, "-o", out, sealed)
	if err := cmdOpen([]string{"-i", oldKey, "-o", filepath.Join(dir, "no.txt"), sealed}); err == nil {
		t.Fatal("a normal open must not fall back to the superseded generation")
	}
	// recover reaches the superseded generation explicitly.
	rescued := filepath.Join(dir, "rescued.txt")
	mustRun(t, cmdRecover, "-i", oldKey, "-o", rescued, sealed)
	if got, err := os.ReadFile(rescued); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("recover did not produce the payload: %v", err)
	}

	// repair completes the scrub, after which recovery finds nothing older.
	mustRun(t, cmdRepair, "-i", newKey, sealed)
	if !inspectFile(t, sealed).Arena.Scrubbed {
		t.Fatal("repair did not leave a scrubbed arena")
	}
	if err := cmdRecover([]string{"-i", oldKey, "-o", filepath.Join(dir, "gone.txt"), sealed}); err == nil {
		t.Fatal("after repair the superseded policy must be gone")
	}
}

// interruptRotation performs the first half of the commit protocol and stops,
// leaving the arena in the state a crash between the two writes produces.
func interruptRotation(t *testing.T, path, idPath, newPub string) {
	t.Helper()
	id, err := loadIdentity(idPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := loadRecipient(newPub)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := box.RewrapAt(t.Context(), &haltAfterFirstCommit{inner: f}, id, nil,
		box.RewrapAtOptions{Seal: box.SealOptions{Recipients: [][]byte{pub}}}); err == nil {
		t.Fatal("expected the simulated interruption to surface")
	}
}

type haltAfterFirstCommit struct {
	inner  *os.File
	writes int
}

func (h *haltAfterFirstCommit) ReadAt(p []byte, off int64) (int, error) {
	return h.inner.ReadAt(p, off)
}

func (h *haltAfterFirstCommit) WriteAt(p []byte, off int64) (int, error) {
	h.writes++
	if h.writes > 1 {
		return 0, os.ErrClosed
	}
	return h.inner.WriteAt(p, off)
}

func (h *haltAfterFirstCommit) Sync() error { return h.inner.Sync() }
