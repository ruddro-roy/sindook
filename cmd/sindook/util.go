package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// openInput opens arg for reading, treating "" and "-" as stdin. size is -1
// when the input is not a regular file.
func openInput(arg string) (r io.ReadCloser, name string, size int64, err error) {
	if arg == "" || arg == "-" {
		return os.Stdin, "", -1, nil
	}
	f, err := os.Open(arg)
	if err != nil {
		return nil, "", -1, err
	}
	size = -1
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
		size = info.Size()
	}
	return f, arg, size, nil
}

// withOutput creates path (refusing to clobber without force), runs fn, and
// removes the partial file if fn fails. binaryGuard refuses to stream
// ciphertext onto an interactive terminal.
func withOutput(path string, force, binaryGuard bool, fn func(io.Writer) error) error {
	if path == "-" {
		if binaryGuard && term.IsTerminal(int(os.Stdout.Fd())) {
			return errors.New("sindook: refusing to write ciphertext to a terminal, use -o or -a")
		}
		return fn(os.Stdout)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func writeFileNew(path string, data []byte, perm os.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// limitedWriter fails once more than n bytes are written, bounding the
// decrypted size of files that should be small (identity files).
type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("sindook: decrypted content larger than expected")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}

// readPassfile reads a passphrase from the first line of a file, the
// scripting alternative to the interactive prompt.
func readPassfile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pass, _, _ := bytes.Cut(raw, []byte("\n"))
	pass = bytes.TrimSuffix(pass, []byte("\r"))
	if len(pass) == 0 {
		return nil, fmt.Errorf("sindook: empty passphrase in %s", path)
	}
	return pass, nil
}

const progressMin = 16 << 20

// withProgress reports progress on stderr while r is consumed, so sealing a
// terabyte does not look like a hang. It stays silent for small inputs,
// unknown sizes, and non-terminal stderr.
func withProgress(r io.Reader, size int64, label string) io.Reader {
	if size < progressMin || !term.IsTerminal(int(os.Stderr.Fd())) {
		return r
	}
	return &progressReader{r: r, label: label, total: size}
}

type progressReader struct {
	r     io.Reader
	label string
	total int64
	done  int64
	last  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if now := time.Now(); err == nil && now.Sub(p.last) >= 150*time.Millisecond {
		p.last = now
		fmt.Fprintf(os.Stderr, "\r\x1b[2K%s  %s / %s (%d%%)",
			p.label, humanBytes(p.done), humanBytes(p.total), p.done*100/p.total)
	}
	if err != nil && !p.last.IsZero() {
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
	return n, err
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
