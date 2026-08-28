package xwing

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestWipeLifecycleSerial pins down the deterministic serial lifecycle
// contract of Wipe: after Wipe returns, decapsulation fails, the seed reads
// as zeroes, the public key remains available, a second Wipe is a harmless
// no-op, and generating a fresh key afterwards works end to end.
func TestWipeLifecycleSerial(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	if len(pub) != PublicKeySize {
		t.Fatalf("public key is %d bytes", len(pub))
	}
	ss, ct, err := Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatalf("decapsulate before wipe: %v", err)
	}
	if !bytes.Equal(got, ss) {
		t.Fatal("decapsulate before wipe produced the wrong secret")
	}

	k.Wipe()

	if _, err := k.Decapsulate(ct); err == nil {
		t.Fatal("decapsulation succeeded after Wipe")
	}
	k.Wipe() // idempotent: must not panic or change the observable state
	if _, err := k.Decapsulate(ct); err == nil {
		t.Fatal("decapsulation succeeded after second Wipe")
	}
	if !allZero(k.Seed()) {
		t.Fatal("Seed did not return zeroes after Wipe")
	}
	if !bytes.Equal(k.PublicKey(), pub) {
		t.Fatal("PublicKey changed after Wipe")
	}

	rek, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey after wipe: %v", err)
	}
	if allZero(rek.Seed()) {
		t.Fatal("freshly generated key has an all-zero seed")
	}
	ss2, ct2, err := Encapsulate(rek.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	got2, err := rek.Decapsulate(ct2)
	if err != nil {
		t.Fatalf("decapsulate on regenerated key: %v", err)
	}
	if !bytes.Equal(got2, ss2) {
		t.Fatal("regenerated key round trip failed")
	}
}

// TestConcurrentWipeStress hammers a single key with decapsulators, seed and
// public key readers, and wipers all at once, under the race detector. The
// invariants it asserts are the concurrency contract of Wipe:
//
//   - no panics, and no torn reads: Seed returns either the original seed or
//     all zeroes, never anything in between, and PublicKey is always the
//     original public key;
//   - the linearization holds: every decapsulation that succeeds must have
//     started before the first Wipe returned;
//   - after a final Wipe returns, every subsequent decapsulation errors.
func TestConcurrentWipeStress(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	origSeed := k.Seed()
	ss, ct, err := Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}

	storm := 1 * time.Second
	if testing.Short() {
		storm = 200 * time.Millisecond
	}

	const (
		decapWorkers  = 16
		readerWorkers = 8
		wipeWorkers   = 4
	)

	done := make(chan struct{})
	var (
		wg sync.WaitGroup

		// wipeCount increments after each Wipe returns. A decapsulator
		// snapshots it BEFORE calling Decapsulate: because Wipe is sticky
		// and Decapsulate holds the key mutex for its whole operation, a
		// decapsulation can only succeed if zero wipes had returned when it
		// began. Counting wipes instead of comparing time.Now() readings
		// across goroutines keeps the linearization check exact — coarse
		// clocks (0.5 ms granularity on Windows) make two calls in the same
		// tick read equal, which a Before comparison then misreads as
		// ordering.
		wipeCount atomic.Int64

		successMu  sync.Mutex
		successAt  []int64
		observMu   sync.Mutex
		badSeeds   int
		badPubs    int
		badSecrets int
	)

	for i := 0; i < decapWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				started := wipeCount.Load()
				got, err := k.Decapsulate(ct)
				if err != nil {
					continue
				}
				if !bytes.Equal(got, ss) {
					observMu.Lock()
					badSecrets++
					observMu.Unlock()
				}
				successMu.Lock()
				successAt = append(successAt, started)
				successMu.Unlock()
			}
		}()
	}

	for i := 0; i < readerWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if s := k.Seed(); !bytes.Equal(s, origSeed) && !allZero(s) {
					observMu.Lock()
					badSeeds++
					observMu.Unlock()
				}
				if p := k.PublicKey(); !bytes.Equal(p, pub) {
					observMu.Lock()
					badPubs++
					observMu.Unlock()
				}
			}
		}()
	}

	// Wait until at least one decapsulation has succeeded before releasing
	// the wipes: once any Wipe has returned, every later decapsulation must
	// fail, so successes can only happen in this window. Waiting for a real
	// success instead of a fixed head start keeps the success-path
	// assertion deterministic on slow, loaded runners, where a fixed 10 ms
	// head start can expire before a single decapsulation completes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		successMu.Lock()
		n := len(successAt)
		successMu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(done)
			wg.Wait()
			t.Fatal("no decapsulation succeeded before the wipes started; the success path could not be exercised")
		}
		runtime.Gosched()
	}

	for i := 0; i < wipeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				k.Wipe()
				wipeCount.Add(1)
				// Yield so decapsulators and readers get a fair shot at the
				// mutex instead of a tight wipe loop holding it by mutex
				// handoff for the whole storm.
				runtime.Gosched()
			}
		}()
	}

	time.Sleep(storm)
	close(done)
	wg.Wait()

	// The storm must have exercised both outcomes: some decapsulations
	// succeeded before the first wipe, and at least one wipe completed.
	observMu.Lock()
	seeds, pubs, secrets := badSeeds, badPubs, badSecrets
	observMu.Unlock()
	if seeds != 0 {
		t.Fatalf("%d Seed() calls observed a torn, partially wiped seed", seeds)
	}
	if pubs != 0 {
		t.Fatalf("%d PublicKey() calls observed a modified public key", pubs)
	}
	if secrets != 0 {
		t.Fatalf("%d successful decapsulations produced a wrong shared secret", secrets)
	}
	wipes := wipeCount.Load()
	successMu.Lock()
	successes := append([]int64(nil), successAt...)
	successMu.Unlock()
	if wipes == 0 {
		t.Fatal("no Wipe completed during the storm")
	}
	if len(successes) == 0 {
		t.Fatal("no decapsulation succeeded during the storm; the success path was not exercised")
	}
	for _, s := range successes {
		if s != 0 {
			t.Fatalf("decapsulation began after %d wipe(s) had already returned, yet succeeded", s)
		}
	}

	// After the final Wipe returns, every subsequent decapsulation must
	// error, Seed must read as zeroes, and PublicKey must be unchanged.
	k.Wipe()
	for i := 0; i < 100; i++ {
		if _, err := k.Decapsulate(ct); err == nil {
			t.Fatal("decapsulation succeeded after the final Wipe returned")
		}
	}
	if !allZero(k.Seed()) {
		t.Fatal("Seed not all-zero after the final Wipe")
	}
	if !bytes.Equal(k.PublicKey(), pub) {
		t.Fatal("PublicKey changed after the final Wipe")
	}
}
