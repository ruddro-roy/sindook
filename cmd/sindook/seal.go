package main

import (
	"errors"
	"io"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/box"
)

const usageSeal = `usage: sindook seal [-r RECIPIENT]... [-R FILE]... [-p | -passfile FILE]
                    [-a] [-o OUT] [-f] [FILE...]

Seal files to recipients and/or a passphrase. Every recipient and
passphrase becomes a key slot; any one of them opens the file. Each FILE
becomes FILE.sindook; with no FILE, stdin is sealed to stdout.

flags:
  -r RECIPIENT    key file or literal sindookpk1: string, repeatable
  -R FILE         file with one public key per line, repeatable
                  (blank lines and # comments are skipped)
  -p              add a passphrase slot, prompted at the terminal
  -passfile FILE  read the passphrase from FILE instead, implies -p
  -a              armor: ASCII output that survives email and copy-paste
  -o OUT          output path, - for stdout (single FILE only)
  -f              overwrite existing output

examples:
  sindook seal -r my.key.pub report.pdf
  sindook seal -r alice.pub -r bob.pub -p budget.xlsx
  sindook seal -R team.keys *.log
  tar cz src | sindook seal -r my.key.pub -o src.tgz.sindook
  sindook seal -r alice.pub -a -o - secret.txt | pbcopy
`

func cmdSeal(args []string) error {
	fs := newFlagSet("seal", usageSeal)
	var recipients, recipientFiles multiFlag
	fs.Var(&recipients, "r", "")
	fs.Var(&recipientFiles, "R", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	armored := fs.Bool("a", false, "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if *out != "" && len(inputs) > 1 {
		return errors.New("sindook: -o cannot be combined with multiple input files")
	}
	opts, err := buildSealOptions(recipients, recipientFiles, *usePass, *passfile, "passphrase")
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	var errs []error
	for _, in := range inputs {
		if err := sealOne(in, *out, opts, *armored, *force); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func sealOne(inPath, outPath string, opts box.SealOptions, armored, force bool) error {
	in, name, size, err := openInput(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	if outPath == "" {
		if name == "" {
			outPath = "-"
		} else {
			outPath = name + ext
		}
	}
	src := withProgress(in, size, "seal "+name)
	return withOutput(outPath, force, !armored, func(w io.Writer) error {
		if !armored {
			return box.Seal(w, src, opts)
		}
		aw := armor.NewWriter(w)
		if err := box.Seal(aw, src, opts); err != nil {
			return err
		}
		return aw.Close()
	})
}
