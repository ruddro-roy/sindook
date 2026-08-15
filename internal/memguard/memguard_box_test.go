package memguard_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/internal/memguard"
)

// TestLockAllDoesNotOOMWithPassphraseBox is the box-level regression test for
// the memguard OOM. It lives in package memguard_test to avoid an import
// cycle (internal/box imports internal/memguard). It calls LockAll and then
// seals with a passphrase, which internally allocates the Argon2id buffer.
// With the buggy MCL_FUTURE path and low RLIMIT_MEMLOCK this would abort the
// runtime with "cannot allocate 67108864-byte block".
func TestLockAllDoesNotOOMWithPassphraseBox(t *testing.T) {
	if err := memguard.LockAll(); err != nil {
		t.Logf("memguard.LockAll: %v (continuing)", err)
	}
	t.Logf("memguard status: %s", memguard.Status())

	// Small params keep this test fast for -race and CI, but still exercises
	// the same code path. The heavy 64 MiB case is covered by
	// TestMemguardLowLimitStillSeals in cmd/sindook and
	// TestLockAllDoesNotOOMWithPassphrase in this package.
	smallArgon := box.Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}
	pass := []byte("box-regression-pass")
	plain := []byte("small payload after LockAll")

	done := make(chan error, 1)
	go func() {
		var sealed bytes.Buffer
		if err := box.SealPassphrase(&sealed, bytes.NewReader(plain), pass, smallArgon); err != nil {
			done <- err
			return
		}
		var out bytes.Buffer
		if err := box.Open(&out, bytes.NewReader(sealed.Bytes()), nil, pass); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(out.Bytes(), plain) {
			done <- bytes.ErrTooLarge
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SealPassphrase/Open after LockAll failed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("box SealPassphrase after LockAll timed out (possible memguard deadlock/OOM)")
	}
}

// TestLockAllHeavyArgon2StillsSeals is guarded by -short because it uses the
// production 64 MiB Argon2 parameters, which are slower under -race.
func TestLockAllHeavyArgon2StillSeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy argon2 in -short mode")
	}
	if err := memguard.LockAll(); err != nil {
		t.Logf("memguard.LockAll: %v", err)
	}
	pass := []byte("heavy-pass")
	plain := []byte("heavy argon2 payload after LockAll")
	done := make(chan error, 1)
	go func() {
		var sealed bytes.Buffer
		if err := box.SealPassphrase(&sealed, bytes.NewReader(plain), pass, box.DefaultArgon2id); err != nil {
			done <- err
			return
		}
		var out bytes.Buffer
		done <- box.Open(&out, bytes.NewReader(sealed.Bytes()), nil, pass)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("heavy SealPassphrase after LockAll failed: %v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("heavy SealPassphrase after LockAll timed out")
	}
}
