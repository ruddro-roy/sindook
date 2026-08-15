package memguard

import "testing"

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
