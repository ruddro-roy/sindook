package memguard

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestWipe(t *testing.T) {
	b := make([]byte, 64)
	for i := range b {
		b[i] = 0xff
	}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %#x", i, v)
		}
	}
	if len(b) != 64 || cap(b) != 64 {
		t.Fatalf("length/capacity changed: len=%d cap=%d", len(b), cap(b))
	}
}

func TestWipeEmpty(t *testing.T) {
	Wipe(nil)
	Wipe([]byte{})
	Wipe(make([]byte, 0, 16))
}

func TestLockAll(t *testing.T) {
	if err := LockAll(); err != nil {
		t.Skipf("memory locking unavailable: %v", err)
	}
	if got := Status(); got != "locked" {
		t.Fatalf("Status() = %q, want %q", got, "locked")
	}
}

// TestLockAllDoesNotOOMWithPassphrase reproduces the ubuntu CI failure:
// with a low RLIMIT_MEMLOCK, LockAll previously used MCL_FUTURE and the
// next 64 MiB argon2id allocation (used for passphrase slots) faulted as
// VM_LOCKED, causing the Go runtime to abort with OOM. The fix falls back
// to MCL_CURRENT under low limits. This test calls LockAll and then
// performs the same large allocation that box.SealPassphrase would, ensuring
// no OOM or hang.
func TestLockAllDoesNotOOMWithPassphrase(t *testing.T) {
	if err := LockAll(); err != nil {
		t.Logf("LockAll: %v (continuing, sealing should still succeed)", err)
	}
	t.Logf("Status after LockAll: %s", Status())

	// Use timeout to avoid hanging the suite if locking regresses.
	done := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		// Same parameters as box.DefaultArgon2id (m=64 MiB, t=3, p=4).
		// We call argon2 directly to avoid an import cycle with box.
		defer func() {
			if r := recover(); r != nil {
				errCh <- r.(error)
			}
		}()
		key := argon2.IDKey([]byte("correct horse battery staple"), bytes.Repeat([]byte{0x42}, 16), 3, 64*1024, 4, 32)
		done <- key
	}()
	select {
	case key := <-done:
		if len(key) != 32 {
			t.Fatalf("argon2 key length = %d, want 32", len(key))
		}
		Wipe(key)
		// Also verify a subsequent plain 64 MiB allocation still works.
		b := make([]byte, 64*1024*1024)
		for i := range b {
			b[i] = byte(i & 0xff)
		}
		if len(b) != 64*1024*1024 {
			t.Fatalf("large allocation failed")
		}
		Wipe(b)
		// Small KDF should also succeed (fast path used by other tests).
		small := argon2.IDKey([]byte("p"), bytes.Repeat([]byte{0x01}, 16), 1, 8, 1, 32)
		if len(small) != 32 {
			t.Fatalf("small argon2 key length = %d", len(small))
		}
		Wipe(small)
	case err := <-errCh:
		t.Fatalf("argon2 panicked after LockAll (possible OOM): %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("argon2 KDF timed out after LockAll (possible memguard deadlock/OOM)")
	}
}

// TestLockAllWipeInterplay verifies Wipe does not alter slice header after
// LockAll, and that multiple Wipe/LockAll interleavings remain safe.
func TestLockAllWipeInterplay(t *testing.T) {
	_ = LockAll()
	for i := 0; i < 3; i++ {
		b := make([]byte, 8*1024)
		for j := range b {
			b[j] = 0xff
		}
		Wipe(b)
		for j, v := range b {
			if v != 0 {
				t.Fatalf("iter %d: byte %d not zeroed", i, j)
			}
		}
		if len(b) != 8*1024 || cap(b) != 8*1024 {
			t.Fatalf("iter %d: len/cap changed", i)
		}
	}
}
