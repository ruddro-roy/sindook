package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// gzipCompress returns a reader that yields the gzip-compressed form of src.
// seal -z uses it so plaintext is compressed before it is encrypted and
// compressed bytes never leave the process in the clear. It returns the pipe
// reader so a caller whose consumer fails can CloseWithError it, which
// unblocks the compressor goroutine instead of leaking it on a full pipe.
func gzipCompress(src io.Reader) *io.PipeReader {
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

// limitWriter fails once more than n bytes are written through it, bounding
// how much a decompression bomb can expand to. n <= 0 means unlimited.
type limitWriter struct {
	w     io.Writer
	limit int64
	wrote int64
}

var errDecompressedTooLarge = errors.New("sindook: decompressed output exceeded the -max-decompressed limit")

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.limit > 0 && l.wrote+int64(len(p)) > l.limit {
		return 0, fmt.Errorf("%w (%s); raise -max-decompressed or set it to 0 for unlimited", errDecompressedTooLarge, humanBytes(l.limit))
	}
	n, err := l.w.Write(p)
	l.wrote += int64(n)
	return n, err
}

// withDecompression runs fn with a writer that collects decrypted plaintext
// and forwards the decompressed form of that gzip stream to dst. fn is
// box.Open, so a byte only reaches the decompressor after its chunk has
// authenticated. The gzip checksum is verified by the final read, so a
// corrupted stream fails instead of writing bad output. limit bounds the
// decompressed size (0 means unlimited).
//
// The reader end of the pipe is always closed when the decompressor stops,
// for any reason. Without that, a mid-stream gzip error would leave the
// goroutine without draining the pipe, and box.Open would block forever on a
// full 64 KiB pipe buffer: a deadlock on any input larger than the buffer.
func withDecompression(dst io.Writer, limit int64, fn func(io.Writer) error) error {
	pr, pw := io.Pipe()
	var copyErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Unblock the writer no matter how this goroutine exits, so fn can
		// never deadlock on a pipe nobody drains.
		defer pr.CloseWithError(errDecompressorStopped)
		gr, err := gzip.NewReader(pr)
		if err != nil {
			copyErr = decompressError(err)
			return
		}
		var out io.Writer = dst
		if limit > 0 {
			out = &limitWriter{w: dst, limit: limit}
		}
		if _, err := io.Copy(out, gr); err != nil {
			copyErr = decompressError(err)
		}
	}()
	ferr := fn(pw)
	pw.CloseWithError(ferr)
	<-done
	if ferr != nil {
		// When decompression stopped first, fn fails with the pipe teardown
		// sentinel. The decompressor's copyErr carries the real cause (a
		// corrupt stream or the -max-decompressed limit), so prefer it.
		if copyErr != nil && errors.Is(ferr, errDecompressorStopped) {
			return copyErr
		}
		return ferr
	}
	return copyErr
}

// errDecompressorStopped closes the pipe read end whenever decompression
// ends before the producer does. Producers report it as their own write
// error, but withDecompression always prefers the decompressor's copyErr or
// the producer's ferr, so it never surfaces on its own.
var errDecompressorStopped = errors.New("sindook: decompression stopped early")

// decompressError keeps the -z guidance attached to every decompression
// failure, including the ones the limit writer raises.
func decompressError(err error) error {
	if errors.Is(err, errDecompressedTooLarge) {
		return err
	}
	return fmt.Errorf("sindook: decompression failed: %w (if this file was sealed without -z, run open without -z)", err)
}

// parseSize accepts a byte count with an optional binary size unit, so
// -max-decompressed can be given as 512K, 8MiB, 2G, or a plain number.
// It returns an error for anything ambiguous or negative.
func parseSize(s string) (int64, error) {
	t := strings.TrimSpace(strings.ToLower(s))
	if t == "" {
		return 0, usagef("empty size")
	}
	unit := int64(1)
	switch {
	case strings.HasSuffix(t, "kib"):
		unit, t = 1<<10, strings.TrimSuffix(t, "kib")
	case strings.HasSuffix(t, "mib"):
		unit, t = 1<<20, strings.TrimSuffix(t, "mib")
	case strings.HasSuffix(t, "gib"):
		unit, t = 1<<30, strings.TrimSuffix(t, "gib")
	case strings.HasSuffix(t, "tib"):
		unit, t = 1<<40, strings.TrimSuffix(t, "tib")
	case strings.HasSuffix(t, "kb"):
		unit, t = 1<<10, strings.TrimSuffix(t, "kb")
	case strings.HasSuffix(t, "mb"):
		unit, t = 1<<20, strings.TrimSuffix(t, "mb")
	case strings.HasSuffix(t, "gb"):
		unit, t = 1<<30, strings.TrimSuffix(t, "gb")
	case strings.HasSuffix(t, "tb"):
		unit, t = 1<<40, strings.TrimSuffix(t, "tb")
	case strings.HasSuffix(t, "k"):
		unit, t = 1<<10, strings.TrimSuffix(t, "k")
	case strings.HasSuffix(t, "m"):
		unit, t = 1<<20, strings.TrimSuffix(t, "m")
	case strings.HasSuffix(t, "g"):
		unit, t = 1<<30, strings.TrimSuffix(t, "g")
	case strings.HasSuffix(t, "t"):
		unit, t = 1<<40, strings.TrimSuffix(t, "t")
	case strings.HasSuffix(t, "b"):
		t = strings.TrimSuffix(t, "b")
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, usagef("invalid size %q: use a byte count like 1073741824, 1G, or 512MiB (0 means unlimited)", s)
	}
	if n != 0 && (n > (1<<63-1)/unit) {
		return 0, usagef("size %q overflows", s)
	}
	return n * unit, nil
}
