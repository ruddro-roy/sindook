package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/internal/memguard"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// parseInterspersedFlags accepts flags before or after file operands. The Go
// flag package intentionally stops at the first operand, which is surprising
// in a file-oriented CLI and breaks common Windows and PowerShell workflows
// such as "sindook seal report.pdf -r alice.pub". A literal filename beginning
// with '-' remains available after "--".
func parseInterspersedFlags(fs *flag.FlagSet, args []string) {
	boolFlags := make(map[string]bool)
	knownFlags := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		knownFlags[f.Name] = true
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			boolFlags[f.Name] = true
		}
	})

	var flags, operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// If there is no earlier operand, flag.Parse still needs the
			// delimiter to keep a leading-dash filename literal. Once an
			// operand exists it has already stopped parsing flags, so carrying
			// the delimiter into fs.Args would incorrectly turn it into a file.
			if len(operands) == 0 {
				operands = append(operands, "--")
			}
			operands = append(operands, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}

		name := strings.TrimLeft(arg, "-")
		hasValue := strings.Contains(name, "=")
		if hasValue {
			name, _, _ = strings.Cut(name, "=")
		}
		// Put unknown flags first too, preserving flag's familiar diagnostic.
		flags = append(flags, arg)
		if knownFlags[name] && !boolFlags[name] && !hasValue && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	fs.Parse(append(flags, operands...))
}

// expandInputs appends deterministic filesystem glob matches to explicit
// operands. It gives cmd.exe and PowerShell users the same batch capability
// as shells that expand wildcards themselves, without changing the meaning of
// ordinary literal file arguments.
func expandInputs(inputs, patterns []string) ([]string, error) {
	expanded := append([]string(nil), inputs...)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("sindook: invalid glob %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("sindook: glob %q matched no files", pattern)
		}
		expanded = append(expanded, matches...)
	}
	return expanded, nil
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
// removes a partial new file if fn fails. With -f, it stages output beside an
// existing destination and replaces it only after a successful close, so a
// failed operation never destroys the previous file. binaryGuard refuses to stream
// ciphertext onto an interactive terminal.
func withOutput(path string, force, binaryGuard bool, fn func(io.Writer) error) error {
	if path == "-" {
		if binaryGuard && term.IsTerminal(int(os.Stdout.Fd())) {
			return errors.New("sindook: refusing to write ciphertext to a terminal, use -o or -a")
		}
		return fn(os.Stdout)
	}
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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

	return writeOutputStaged(path, 0o600, fn)
}

// writeOutputStaged replaces a regular output only after fn completes.
// The replacement always receives perm so plaintext and ciphertext outputs do
// not inherit broad permissions from an older destination.
func writeOutputStaged(path string, perm os.FileMode, fn func(io.Writer) error) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sindook: refusing to overwrite symbolic link %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("sindook: refusing to overwrite non-regular file %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), ".sindook-output-*")
	if err != nil {
		return err
	}
	cleanup := func() {
		f.Close()
		os.Remove(f.Name())
	}
	if err := f.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if err := fn(f); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return replaceStaged(f.Name(), path)
}

func writeFileNew(path string, data []byte, perm os.FileMode, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
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

	return writeOutputStaged(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// preflightOutput checks every output in a multi-file operation before the
// first write. It is used for identity pairs so an existing public key cannot
// leave behind a newly-created private key when key generation fails.
func preflightOutput(path string, force bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !force {
		return &os.PathError{Op: "open", Path: path, Err: os.ErrExist}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sindook: refusing to overwrite symbolic link %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("sindook: refusing to overwrite non-regular file %s", path)
	}
	return nil
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
// scripting alternative to the interactive prompt. The returned passphrase
// lives in a fresh buffer the caller must wipe when done; the file contents
// are zeroed here. A file readable by other accounts earns a warning.
func readPassfile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer memguard.Wipe(raw)
	if info, statErr := os.Stat(path); statErr == nil {
		if warning := warnInsecurePerms(path, info); warning != "" {
			fmt.Fprintln(os.Stderr, warning)
		}
	}
	pass, _, _ := bytes.Cut(raw, []byte("\n"))
	pass = bytes.TrimSuffix(pass, []byte("\r"))
	if len(pass) == 0 {
		return nil, fmt.Errorf("sindook: empty passphrase in %s", path)
	}
	pass = append([]byte(nil), pass...)
	return pass, nil
}

const progressMin = 16 << 20

// wipePassphrases zeroes every passphrase buffer in opts once sealing is
// finished, and wipeIdentity zeroes a loaded private key. Command handlers
// defer these so secrets do not outlive the run.
func wipePassphrases(opts *box.SealOptions) {
	for _, p := range opts.Passphrases {
		memguard.Wipe(p)
	}
	opts.Passphrases = nil
}

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
