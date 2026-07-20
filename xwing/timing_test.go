package xwing

import (
	"crypto/rand"
	"math"
	mrand "math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"testing"
	"time"
)

// TestDecapsulationTiming is a dudect-style leakage check (Reparaz, Balasch,
// Verbauwhede): decapsulating a valid ciphertext and a random well-sized
// ciphertext (the implicit-rejection path) must be indistinguishable in
// time, or the ML-KEM implicit rejection leaks through a side channel.
//
// Several harness lessons are baked in from watching naive versions fail on a
// busy laptop. A reused fixed buffer measures its own L1 residency, so every
// input gets a distinct heap allocation. Unpaired sampling reads thermal and
// scheduler drift as a false signal, so each pair is measured back to back in
// randomized order and the per-pair difference is tested, which cancels
// drift. A constant valid ciphertext is more branch-predictor and cache
// friendly than random bytes, leaking constant-vs-varying rather than
// valid-vs-rejected, so both classes use freshly encapsulated or freshly
// random content and only key validity differs.
//
// The remaining problem is that a first-order dudect test is only meaningful
// on a quiet machine, and this repo is developed on a shared 8 GB laptop. So
// the test establishes its own noise floor: a null measurement of valid
// against independent valid (identical distribution, so the true t is zero)
// runs alongside the real valid-against-random measurement. If the null is
// itself elevated the machine is too noisy and the test skips with the
// numbers rather than issuing a false verdict; only a quiet null plus a loud
// real result is reported as a leak. Runs only with SINDOOK_TIMING=1.
func TestDecapsulationTiming(t *testing.T) {
	if os.Getenv("SINDOOK_TIMING") != "1" {
		t.Skip("set SINDOOK_TIMING=1 to run the timing check")
	}

	id, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	const warmup = 1000
	const pairs = 20000

	genValid := func() [][]byte {
		cts := make([][]byte, pairs)
		for i := range cts {
			_, ct, err := Encapsulate(id.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			cts[i] = ct
		}
		return cts
	}
	validA := genValid()
	validB := genValid()
	random := make([][]byte, pairs)
	for i := range random {
		ct := make([]byte, CiphertextSize)
		if _, err := rand.Read(ct); err != nil {
			t.Fatal(err)
		}
		random[i] = ct
	}

	// One shared order schedule so the null and the real measurement see the
	// same first/second placement pattern.
	aFirst := make([]bool, pairs)
	rng := mrand.New(mrand.NewSource(1))
	for i := range aFirst {
		aFirst[i] = rng.Intn(2) == 0
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	for i := 0; i < warmup; i++ {
		_, _ = id.Decapsulate(validA[i])
		_, _ = id.Decapsulate(random[i])
	}

	nullT, nullMean := pairedT(id, validA, validB, aFirst)
	realT, realMean := pairedT(id, validA, random, aFirst)

	t.Logf("null (valid vs valid): t = %.2f, mean diff %.0f ns", nullT, nullMean)
	t.Logf("real (valid vs random): t = %.2f, mean diff %.0f ns", realT, realMean)

	const threshold = 10
	if math.Abs(nullT) >= threshold {
		t.Skipf("machine too noisy for a verdict: null |t| = %.2f >= %d; run on a quiet, idle host", math.Abs(nullT), threshold)
	}
	if math.Abs(realT) > threshold {
		t.Fatalf("timing distinguishable between valid and implicitly rejected ciphertexts: real |t| = %.2f > %d (null |t| = %.2f)", math.Abs(realT), threshold, math.Abs(nullT))
	}
}

// pairedT measures each a[i]/b[i] pair back to back, with aFirst[i] deciding
// order, and returns the one-sample t statistic of the paired differences
// after trimming the loudest tenth by absolute value. Identical input
// distributions yield a true mean of zero, so the returned t is the harness
// noise floor.
func pairedT(id *PrivateKey, a, b [][]byte, aFirst []bool) (tStat, mean float64) {
	diffs := make([]float64, len(a))
	for i := range a {
		var an, bn int64
		if aFirst[i] {
			an = timeOne(id, a[i])
			bn = timeOne(id, b[i])
		} else {
			bn = timeOne(id, b[i])
			an = timeOne(id, a[i])
		}
		diffs[i] = float64(an - bn)
	}
	kept := trimAbs(diffs, 0.9)
	mean, variance := meanVar(kept)
	return mean / math.Sqrt(variance/float64(len(kept))), mean
}

func timeOne(id *PrivateKey, ct []byte) int64 {
	start := time.Now()
	_, _ = id.Decapsulate(ct)
	return time.Since(start).Nanoseconds()
}

// trimAbs keeps the given fraction of samples with the smallest absolute
// value, discarding preemption and interrupt spikes of either sign.
func trimAbs(xs []float64, keep float64) []float64 {
	sorted := append([]float64(nil), xs...)
	sort.Slice(sorted, func(i, j int) bool { return math.Abs(sorted[i]) < math.Abs(sorted[j]) })
	return sorted[:int(float64(len(sorted))*keep)]
}

func meanVar(xs []float64) (mean, variance float64) {
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		d := x - mean
		variance += d * d
	}
	return mean, variance / float64(len(xs)-1)
}
