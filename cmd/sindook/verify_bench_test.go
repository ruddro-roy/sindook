package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// benchmarkVerify seals n files once, then measures cmdVerify runs at a
// fixed worker count. The corpus build runs with stdout and stderr
// redirected, because keygen announces its paths and go test folds the
// binary's stderr into the benchmark output otherwise.
func benchmarkVerify(b *testing.B, n, jobs int) {
	dir := b.TempDir()
	args := []string{"-jobs", fmt.Sprintf("%d", jobs)}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer devnull.Close()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	func() {
		defer func() { os.Stdout, os.Stderr = oldStdout, oldStderr }()
		key, pub := newIdentity(b, dir, "id.key")
		args = append([]string{"-i", key}, args...)
		for i := 0; i < n; i++ {
			f := filepath.Join(dir, fmt.Sprintf("f%03d.txt", i))
			write(b, f, benchPayloadCLI(4<<10))
			mustRun(b, cmdSeal, "-r", pub, f)
			args = append(args, f+ext)
		}
	}()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := captureStdout(b, func() error { return cmdVerify(args) }); err != nil {
			b.Fatal(err)
		}
	}
}

// benchPayloadCLI returns n bytes of incompressible-ish data, matching
// the box benchmark payloads.
func benchPayloadCLI(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

func BenchmarkVerify32FilesSerial(b *testing.B) { benchmarkVerify(b, 32, 1) }
func BenchmarkVerify32FilesJobs4(b *testing.B)  { benchmarkVerify(b, 32, 4) }
func BenchmarkVerify32FilesJobs8(b *testing.B)  { benchmarkVerify(b, 32, 8) }
