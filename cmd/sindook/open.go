package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageOpen = `usage: sindook open (-i IDENTITY | -p | -passfile FILE) [-o OUT] [-f] [FILE...]

Decrypt sealed files. Armored input is detected automatically. Each
FILE.sindook becomes FILE; with no FILE, stdin is opened to stdout.

flags:
  -i IDENTITY     identity file (prompts if passphrase-protected)
  -p              open with a passphrase, prompted at the terminal
  -passfile FILE  read the passphrase from FILE instead
  -o OUT          output path, - for stdout (single FILE only)
  -f              overwrite existing output

examples:
  sindook open -i my.key report.pdf.sindook
  sindook open -p notes.txt.sindook
  sindook open -i my.key -o - src.tgz.sindook | tar xz
`

func cmdOpen(args []string) error {
	fs := newFlagSet("open", usageOpen)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if *out != "" && len(inputs) > 1 {
		return errors.New("sindook: -o cannot be combined with multiple input files")
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "passphrase")
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	var errs []error
	for _, in := range inputs {
		if err := openOne(in, *out, id, pass, *force); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func openOne(inPath, outPath string, id *xwing.PrivateKey, pass []byte, force bool) error {
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
		return box.Open(w, src, id, pass)
	})
}

const usageVerify = `usage: sindook verify (-i IDENTITY | -p | -passfile FILE) [FILE...]

Fully decrypt and authenticate sealed files without writing plaintext
anywhere. Confirms a backup will actually open before you need it. Every
file is checked even if an earlier one fails; the exit code is non-zero if
any did.

flags:
  -i IDENTITY     identity file (prompts if passphrase-protected)
  -p              verify with a passphrase, prompted at the terminal
  -passfile FILE  read the passphrase from FILE instead

example:
  sindook verify -i my.key backups/*.sindook
`

func cmdVerify(args []string) error {
	fs := newFlagSet("verify", usageVerify)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	fs.Parse(args)

	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "passphrase")
	if err != nil {
		return err
	}
	inputs := fs.Args()
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	var errs []error
	for _, inPath := range inputs {
		name, err := verifyOne(inPath, id, pass)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			fmt.Printf("%s: FAILED\n", name)
			continue
		}
		fmt.Printf("%s: ok\n", name)
	}
	return errors.Join(errs...)
}

func verifyOne(inPath string, id *xwing.PrivateKey, pass []byte) (string, error) {
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
	return name, box.Open(io.Discard, src, id, pass)
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
