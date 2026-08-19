package main

import (
	"compress/gzip"
	"fmt"
	"io"
)

// gzipCompress returns a reader that yields the gzip-compressed form of src.
// seal -z uses it so plaintext is compressed before it is encrypted and
// compressed bytes never leave the process in the clear. The pipe goroutine
// ends when src is fully read or the consumer stops reading; a CLI process is
// short-lived, so an abandoned stream costs nothing that matters.
func gzipCompress(src io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		gz := gzip.NewWriter(pw)
		if _, err := io.Copy(gz, src); err != nil {
			pw.CloseWithError(err)
			return
		}
		if err := gz.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.Close()
	}()
	return pr
}

// withDecompression runs fn with a writer that collects decrypted plaintext
// and forwards the decompressed form of that gzip stream to dst. fn is
// box.Open, so a byte only reaches the decompressor after its chunk has
// authenticated. The gzip checksum is verified by the final read, so a
// corrupted stream fails instead of writing bad output.
func withDecompression(dst io.Writer, fn func(io.Writer) error) error {
	pr, pw := io.Pipe()
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		gr, err := gzip.NewReader(pr)
		if err != nil {
			copyErr = decompressError(err)
			pr.CloseWithError(copyErr)
			return
		}
		if _, err := io.Copy(dst, gr); err != nil {
			copyErr = decompressError(err)
		}
	}()
	ferr := fn(pw)
	pw.CloseWithError(ferr)
	<-done
	if ferr != nil {
		return ferr
	}
	return copyErr
}

func decompressError(err error) error {
	return fmt.Errorf("sindook: decompression failed: %w (if this file was sealed without -z, run open without -z)", err)
}
