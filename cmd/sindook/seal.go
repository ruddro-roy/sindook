package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/box"
)

const usageSeal = `usage: sindook seal [-r RECIPIENT]... [-R FILE]... [-p | -passfile FILE]
                    [-format 2|3] [-header-capacity BYTES] [-reserve N]
                    [-a] [-o OUT] [-f] [FILE...]

Seal files to recipients and/or a passphrase. Every recipient and
passphrase becomes a key slot; any one of them opens the file. Each FILE
becomes FILE.sindook; with no FILE, stdin is sealed to stdout.

Format v3, the default, reserves a fixed header arena so later rotations
rewrite only the header and never read the payload. The arena costs a few
kilobytes per file and is what makes "rewrap" bounded. Use -format 2 for
files that must be readable by sindook 0.4.x and earlier.

flags:
  -r RECIPIENT           key file or literal sindookpk1: string, repeatable
  -R FILE                file with one public key per line, repeatable
                         (blank lines and # comments are skipped)
  -p                     add a passphrase slot, prompted at the terminal
  -passfile FILE         read the passphrase from FILE instead, implies -p
  -format N              on-disk format, 3 (default) or 2
  -header-capacity BYTES exact arena slot size, multiple of 4096
  -reserve N             room for N more recipients later (default 4)
  -a                     armor: ASCII output that survives email and copy-paste
  -o OUT                 output path, - for stdout (single FILE only)
  -f                     overwrite existing output

examples:
  sindook seal -r my.key.pub report.pdf
  sindook seal -r alice.pub -r bob.pub -p budget.xlsx
  sindook seal -R team.keys -reserve 16 archive.tar
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
	format := fs.Int("format", 3, "")
	capacity := fs.Int("header-capacity", 0, "")
	reserve := fs.Int("reserve", -1, "")
	armored := fs.Bool("a", false, "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if *out != "" && len(inputs) > 1 {
		return errors.New("sindook: -o cannot be combined with multiple input files")
	}
	if *format != 2 && *format != 3 {
		return fmt.Errorf("sindook: -format must be 2 or 3, got %d", *format)
	}
	if *format == 2 && (*capacity != 0 || *reserve >= 0) {
		return errors.New("sindook: -header-capacity and -reserve apply to format 3 only")
	}
	arena, err := arenaOptions(*capacity, *reserve)
	if err != nil {
		return err
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
		if err := sealOne(in, *out, opts, arena, *format, *armored, *force); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// arenaOptions turns the capacity flags into the library's options. The flag
// default is -1 so that an explicit "-reserve 0", meaning no headroom at all,
// stays distinguishable from the flag not being given.
func arenaOptions(capacity, reserve int) (box.ArenaOptions, error) {
	if capacity < 0 || capacity > 1<<20 {
		return box.ArenaOptions{}, fmt.Errorf("sindook: -header-capacity out of range: %d", capacity)
	}
	a := box.ArenaOptions{SlotCapacity: uint32(capacity)}
	switch {
	case reserve < 0:
		a.ReserveRecipients = 0 // not given: the library default applies
	case reserve == 0:
		a.ReserveRecipients = -1 // given as zero: no headroom
	default:
		a.ReserveRecipients = reserve
	}
	return a, nil
}

func sealOne(inPath, outPath string, opts box.SealOptions, arena box.ArenaOptions, format int, armored, force bool) error {
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
	write := func(w io.Writer) error {
		if format == 2 {
			return box.Seal(w, src, opts)
		}
		return box.SealV3(w, src, opts, arena)
	}
	return withOutput(outPath, force, !armored, func(w io.Writer) error {
		if !armored {
			return write(w)
		}
		aw := armor.NewWriter(w)
		if err := write(aw); err != nil {
			return err
		}
		return aw.Close()
	})
}
