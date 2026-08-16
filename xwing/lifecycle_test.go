package xwing

import (
	"bytes"
	"runtime"
	"sync"
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

		wipeMu     sync.Mutex
		wipeAt     []time.Time
		successMu  sync.Mutex
		successAt  []time.Time
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
				started := time.Now()
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

	// Give the decapsulators a head start so the success path is exercised
	// before the first wipe: once any Wipe has returned, every later
	// decapsulation must fail, so successes can only happen in this window.
	time.Sleep(10 * time.Millisecond)

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
				wipeMu.Lock()
				wipeAt = append(wipeAt, time.Now())
				wipeMu.Unlock()
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
	wipeMu.Lock()
	wipes := append([]time.Time(nil), wipeAt...)
	wipeMu.Unlock()
	successMu.Lock()
	successes := append([]time.Time(nil), successAt...)
	successMu.Unlock()
	if len(wipes) == 0 {
		t.Fatal("no Wipe completed during the storm")
	}
	if len(successes) == 0 {
		t.Fatal("no decapsulation succeeded during the storm; the success path was not exercised")
	}
	firstWipe := wipes[0]
	for _, w := range wipes[1:] {
		if w.Before(firstWipe) {
			firstWipe = w
		}
	}
	for _, s := range successes {
		if !s.Before(firstWipe) {
			t.Fatalf("decapsulation started at %v, after the first Wipe returned at %v, yet succeeded", s, firstWipe)
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
