package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/memguard"
	"github.com/ruddro-roy/sindook/xwing"
)

const maxDecompressedDefault = 1 << 40 // 1 TiB

const usageOpen = `usage: sindook open [-i IDENTITY | -p | -passfile FILE]
                    [-identity-passfile FILE] [-z] [-max-decompressed SIZE]
                    [-glob PATTERN]... [-o OUT] [-f] [FILE...]

Decrypt sealed files. Armored input is detected automatically. Each
FILE.sindook becomes FILE; with no FILE, stdin is opened to stdout.

With no -i, -p, or -passfile, the identity selected by sindook init is
used when one exists.

flags:
  -i IDENTITY     identity file (prompts if passphrase-protected)
                  use @default for the identity selected by sindook init
  -p              open with a passphrase, prompted at the terminal
  -passfile FILE  read the passphrase from FILE instead
  -identity-passfile FILE
                  read a protected identity's passphrase from FILE
  -z              decompress a file sealed with seal -z
  -max-decompressed SIZE
                  cap the decompressed size with -z, for safety against
                  hostile archives; accepts 2G, 512MiB, or a byte count,
                  0 means unlimited (default 1T)
  -glob PATTERN    add files matched by a portable filesystem pattern
  -o OUT          output path, - for stdout (single FILE only)
  -f              overwrite existing output

examples:
  sindook open report.pdf.sindook
  sindook open -z -i my.key photos.tar.sindook
  sindook open -z -max-decompressed 10G archive.tar.sindook
  sindook open -p notes.txt.sindook
`

func cmdOpen(args []string) error {
	fs := newFlagSet("open", usageOpen)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	identityPassfile := fs.String("identity-passfile", "", "")
	decompress := fs.Bool("z", false, "")
	maxDecompressed := fs.String("max-decompressed", "1T", "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	parseInterspersedFlags(fs, args)

	limit, err := parseSize(*maxDecompressed)
	if err != nil {
		return err
	}
	inputs, err := expandInputs(fs.Args(), globs)
	if err != nil {
		return err
	}
	if *out != "" && len(inputs) > 1 {
		return usagef("-o cannot be combined with multiple input files")
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, *identityPassfile, "passphrase")
	if err != nil {
		return err
	}
	if id != nil {
		defer id.Wipe()
	}
	if pass != nil {
		defer memguard.Wipe(pass)
	}
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	var errs []error
	for _, in := range inputs {
		if err := openOne(in, *out, id, pass, *force, *decompress, limit); err != nil {
			// A wrong identity is the common failure; point passphrase-sealed
			// files at -p instead of leaving a bare unwrap error.
			if errors.Is(err, box.ErrWrongKey) && pass == nil {
				err = fmt.Errorf("%w; if this file was sealed with a passphrase, add -p", err)
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func openOne(inPath, outPath string, id *xwing.PrivateKey, pass []byte, force, decompress bool, maxDecompressed int64) error {
	in, name, size, err := openInput(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	if outPath == "" {
		switch {
		case name == "":
			outPath = "-"
		case strings.HasSuffix(name, ext):
			outPath = strings.TrimSuffix(name, ext)
		default:
			return fmt.Errorf("sindook: %s does not end in %s, use -o", name, ext)
		}
	}
	src, _, err := detectArmor(withProgress(in, size, "open "+name))
	if err != nil {
		return err
	}
	return withOutput(outPath, force, false, func(w io.Writer) error {
		if !decompress {
			return box.Open(w, src, id, pass)
		}
		return withDecompression(w, maxDecompressed, func(dw io.Writer) error {
			return box.Open(dw, src, id, pass)
		})
	})
}

const usageVerify = `usage: sindook verify [-i IDENTITY | -p | -passfile FILE]
                      [-identity-passfile FILE] [-z] [-max-decompressed SIZE]
                      [-glob PATTERN]... [-json] [FILE...]

Fully decrypt and authenticate sealed files without writing plaintext
anywhere. Confirms a backup will actually open before you need it. Every
file is checked even if an earlier one fails; the exit code is non-zero if
any did. With no credential flag, the identity selected by sindook init is
used when one exists. With -z, the gzip stream is also decompressed in
memory, confirming a compressed archive is fully recoverable.

flags:
  -i IDENTITY     identity file (prompts if passphrase-protected)
                  use @default for the identity selected by sindook init
  -p              verify with a passphrase, prompted at the terminal
  -passfile FILE  read the passphrase from FILE instead
  -identity-passfile FILE
                  read a protected identity's passphrase from FILE
  -z              also decompress files sealed with seal -z
  -max-decompressed SIZE
                  cap the decompressed size with -z; accepts 2G, 512MiB,
                  or a byte count, 0 means unlimited (default 1T)
  -glob PATTERN    add files matched by a portable filesystem pattern
  -json            print one machine-readable JSON array with per-file
                  status instead of human-readable ok/FAILED lines

example:
  sindook verify -z -i my.key backups/*.sindook
`

type verifyResult struct {
	File   string `json:"file"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func cmdVerify(args []string) error {
	fs := newFlagSet("verify", usageVerify)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	identityPassfile := fs.String("identity-passfile", "", "")
	decompress := fs.Bool("z", false, "")
	maxDecompressed := fs.String("max-decompressed", "1T", "")
	jsonOut := fs.Bool("json", false, "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	parseInterspersedFlags(fs, args)

	limit, err := parseSize(*maxDecompressed)
	if err != nil {
		return err
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, *identityPassfile, "passphrase")
	if err != nil {
		return err
	}
	if id != nil {
		defer id.Wipe()
	}
	if pass != nil {
		defer memguard.Wipe(pass)
	}
	inputs, err := expandInputs(fs.Args(), globs)
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	var errs []error
	results := make([]verifyResult, 0, len(inputs))
	for _, inPath := range inputs {
		name, err := verifyOne(inPath, id, pass, *decompress, limit)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			results = append(results, verifyResult{File: name, Status: "failed", Error: err.Error()})
			continue
		}
		results = append(results, verifyResult{File: name, Status: "ok"})
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			errs = append(errs, err)
		}
	} else {
		for _, res := range results {
			if res.Status == "ok" {
				fmt.Printf("%s: ok\n", res.File)
			} else {
				fmt.Printf("%s: FAILED\n", res.File)
			}
		}
	}
	return errors.Join(errs...)
}

func verifyOne(inPath string, id *xwing.PrivateKey, pass []byte, decompress bool, maxDecompressed int64) (string, error) {
	name := inPath
	if name == "" || name == "-" {
		name = "stdin"
	}
	in, _, size, err := openInput(inPath)
	if err != nil {
		return name, err
	}
	defer in.Close()
	src, _, err := detectArmor(withProgress(in, size, "verify "+name))
	if err != nil {
		return name, err
	}
	if !decompress {
		return name, box.Open(io.Discard, src, id, pass)
	}
	return name, withDecompression(io.Discard, maxDecompressed, func(dw io.Writer) error {
		return box.Open(dw, src, id, pass)
	})
}

// detectArmor sniffs the input and transparently unwraps armored files, so
// commands never need to be told which encoding they are looking at.
func detectArmor(r io.Reader) (io.Reader, bool, error) {
	br := bufio.NewReader(r)
	prefix, err := br.Peek(64)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if armor.IsArmored(prefix) {
		return armor.NewReader(br), true, nil
	}
	return br, false, nil
}
