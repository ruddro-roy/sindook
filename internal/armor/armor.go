// Package armor wraps sindook ciphertext in a PEM-style base64 encoding so
// sealed files survive text-only channels: email, chat, config files,
// copy-paste. Encoding is streaming in both directions and strict on read:
// malformed framing is rejected rather than repaired, because silently
// accepting damaged armor would hide corruption until decryption fails with
// a less specific error.
package armor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const (
	begin = "-----BEGIN SINDOOK ENCRYPTED FILE-----"
	end   = "-----END SINDOOK ENCRYPTED FILE-----"

	cols        = 64
	maxLineLen  = 1024
	maxBodyLine = 76 // accept foreign wrappers up to PEM's 76 columns
)

var (
	ErrMalformed = errors.New("sindook: malformed armor")
	ErrTrailing  = errors.New("sindook: data after armor end line")
)

// IsArmored reports whether b (a prefix of the input, leading whitespace
// allowed) begins an armored file.
func IsArmored(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte(begin))
}

// NewWriter returns a WriteCloser that armors everything written to it onto
// w. Close flushes the final partial line and the end marker; the armor is
// invalid until Close returns nil.
func NewWriter(w io.Writer) io.WriteCloser {
	lw := &lineWriter{w: w}
	return &writer{lw: lw, enc: base64.NewEncoder(base64.StdEncoding, lw)}
}

type writer struct {
	lw      *lineWriter
	enc     io.WriteCloser
	started bool
	closed  bool
}

func (a *writer) start() error {
	if a.started {
		return nil
	}
	a.started = true
	_, err := io.WriteString(a.lw.w, begin+"\n")
	return err
}

func (a *writer) Write(p []byte) (int, error) {
	if a.closed {
		return 0, errors.New("sindook: write to closed armor writer")
	}
	if err := a.start(); err != nil {
		return 0, err
	}
	return a.enc.Write(p)
}

func (a *writer) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	if err := a.start(); err != nil {
		return err
	}
	if err := a.enc.Close(); err != nil {
		return err
	}
	if a.lw.col > 0 {
		if _, err := io.WriteString(a.lw.w, "\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(a.lw.w, end+"\n")
	return err
}

// lineWriter inserts a newline every cols bytes of base64.
type lineWriter struct {
	w   io.Writer
	col int
}

func (l *lineWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := cols - l.col
		if n > len(p) {
			n = len(p)
		}
		if _, err := l.w.Write(p[:n]); err != nil {
			return written, err
		}
		written += n
		l.col += n
		p = p[n:]
		if l.col == cols {
			if _, err := io.WriteString(l.w, "\n"); err != nil {
				return written, err
			}
			l.col = 0
		}
	}
	return written, nil
}

// NewReader returns a Reader that decodes an armored stream from r. Blank
// lines are permitted only before the begin marker and after the end marker;
// body lines must be full base64 groups, and padding may appear only on the
// final body line.
func NewReader(r io.Reader) io.Reader {
	return &reader{br: bufio.NewReader(r)}
}

type reader struct {
	br         *bufio.Reader
	buf        []byte
	started    bool
	done       bool
	sawPadding bool
	err        error
}

func (a *reader) Read(p []byte) (int, error) {
	for len(a.buf) == 0 && a.err == nil {
		a.fill()
	}
	if len(a.buf) > 0 {
		n := copy(p, a.buf)
		a.buf = a.buf[n:]
		return n, nil
	}
	return 0, a.err
}

// readLine returns the next line without its terminator, enforcing a length
// cap so a hostile stream cannot force unbounded buffering.
func (a *reader) readLine() (string, error) {
	line, err := a.br.ReadString('\n')
	if len(line) > maxLineLen {
		return "", ErrMalformed
	}
	if err == io.EOF && line == "" {
		return "", io.EOF
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (a *reader) fill() {
	line, err := a.readLine()
	if err != nil {
		if err == io.EOF && !a.done {
			err = ErrMalformed
		}
		a.err = err
		return
	}

	if !a.started {
		switch strings.TrimSpace(line) {
		case "":
			return
		case begin:
			a.started = true
			return
		default:
			a.err = ErrMalformed
			return
		}
	}

	if a.done {
		if strings.TrimSpace(line) != "" {
			a.err = ErrTrailing
		}
		return
	}

	if line == end {
		a.done = true
		return
	}
	if a.sawPadding || line == "" || len(line) > maxBodyLine || len(line)%4 != 0 {
		a.err = ErrMalformed
		return
	}
	if strings.Contains(line, "=") {
		a.sawPadding = true
	}
	dec, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		a.err = ErrMalformed
		return
	}
	a.buf = dec
}
