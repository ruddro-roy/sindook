package box

import (
	"bytes"
	"io"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// benchKeyPairs caches one identity per benchmark run: X-Wing keygen is
// expensive relative to the per-file operations being measured.
var benchIdentity *xwing.PrivateKey

func benchID(b *testing.B) *xwing.PrivateKey {
	if benchIdentity == nil {
		id, err := xwing.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		benchIdentity = id
	}
	return benchIdentity
}

// benchPayload returns n bytes of incompressible-ish data so compression
// (when enabled) cannot trivially shrink it.
func benchPayload(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

func benchSealOptions(b *testing.B) SealOptions {
	return SealOptions{Recipients: [][]byte{benchID(b).PublicKey()}, Argon: DefaultArgon2id}
}

func benchmarkSeal(b *testing.B, size int) {
	b.SetBytes(int64(size))
	opts := benchSealOptions(b)
	payload := benchPayload(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := Seal(&out, bytes.NewReader(payload), opts); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkOpen(b *testing.B, size int) {
	b.SetBytes(int64(size))
	id := benchID(b)
	opts := benchSealOptions(b)
	payload := benchPayload(size)
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(payload), opts); err != nil {
		b.Fatal(err)
	}
	blob := sealed.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Open(io.Discard, bytes.NewReader(blob), id, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeal64KiB(b *testing.B) { benchmarkSeal(b, 64<<10) }
func BenchmarkSeal1MiB(b *testing.B)  { benchmarkSeal(b, 1<<20) }
func BenchmarkSeal64MiB(b *testing.B) { benchmarkSeal(b, 64<<20) }
func BenchmarkOpen64KiB(b *testing.B) { benchmarkOpen(b, 64<<10) }
func BenchmarkOpen1MiB(b *testing.B)  { benchmarkOpen(b, 1<<20) }
func BenchmarkOpen64MiB(b *testing.B) { benchmarkOpen(b, 64<<20) }

// BenchmarkRewrapFast measures the slot-swap path on a 1 MiB payload:
// the whole file is copied but the payload is never decrypted or
// re-encrypted.
func BenchmarkRewrapFast(b *testing.B) {
	b.SetBytes(1 << 20)
	id := benchID(b)
	payload := benchPayload(1 << 20)
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(payload), benchSealOptions(b)); err != nil {
		b.Fatal(err)
	}
	blob := sealed.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := Rewrap(&out, bytes.NewReader(blob), id, nil, benchSealOptions(b), false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRewrapDeep measures full re-encryption of the same payload.
func BenchmarkRewrapDeep(b *testing.B) {
	b.SetBytes(1 << 20)
	id := benchID(b)
	payload := benchPayload(1 << 20)
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(payload), benchSealOptions(b)); err != nil {
		b.Fatal(err)
	}
	blob := sealed.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := Rewrap(&out, bytes.NewReader(blob), id, nil, benchSealOptions(b), true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSealMultiRecipient measures slot cost with 8 recipients on a
// small payload, where encapsulation dominates. The same public key is
// repeated eight times on purpose: box.Seal does not dedupe recipients,
// so each slot pays real encapsulation cost.
func BenchmarkSealMultiRecipient(b *testing.B) {
	pub := benchID(b).PublicKey()
	opts := SealOptions{Argon: DefaultArgon2id}
	for i := 0; i < 8; i++ {
		opts.Recipients = append(opts.Recipients, pub)
	}
	payload := benchPayload(16 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := Seal(&out, bytes.NewReader(payload), opts); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSealPassphrase measures the Argon2id KDF path (RFC 9106
// parameters), which dominates sealing with a passphrase slot.
func BenchmarkSealPassphrase(b *testing.B) {
	payload := benchPayload(16 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := SealPassphrase(&out, bytes.NewReader(payload), []byte("bench-passphrase"), DefaultArgon2id); err != nil {
			b.Fatal(err)
		}
	}
}
