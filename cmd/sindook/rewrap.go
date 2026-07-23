package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageRewrap = `usage: sindook rewrap (-i IDENTITY | -p | -passfile FILE)
                      (-r RECIPIENT)... [-R FILE]...
                      [-new-passphrase | -new-passfile FILE]
                      [-deep] [-o OUT] [-f] FILE...

Replace the key slots of sealed files. By default only the header is
rewritten: rotation costs the same for a kilobyte or a terabyte, and
plaintext never exists anywhere. Fast mode does not retroactively revoke
someone who kept a copy of the old file; -deep re-encrypts the payload
under a fresh key and does. Files are rewritten in place atomically unless
-o is given. Rotating a whole directory of files in one run is the
intended use.

flags:
  -i IDENTITY         identity that opens the files today
  -p                  open with the current passphrase (prompted)
  -passfile FILE      read the current passphrase from FILE
  -r RECIPIENT        new recipient, repeatable
  -R FILE             file of new recipients, one key per line, repeatable
  -new-passphrase     add a new passphrase slot (prompted)
  -new-passfile FILE  read the new passphrase from FILE
  -deep               re-encrypt the payload under a fresh file key
  -o OUT              output path, - for stdout (single FILE only)
  -f                  overwrite existing output

examples:
  sindook rewrap -i my.key -r alice.pub -r bob.pub archive.tar.sindook
  sindook rewrap -i my.key -r alice.pub -deep archive.tar.sindook
  sindook rewrap -i old.key -R team.keys backups/*.sindook
`

func cmdRewrap(args []string) error {
	fs := newFlagSet("rewrap", usageRewrap)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	var recipients, recipientFiles multiFlag
	fs.Var(&recipients, "r", "")
	fs.Var(&recipientFiles, "R", "")
	newPass := fs.Bool("new-passphrase", false, "")
	newPassfile := fs.String("new-passfile", "", "")
	deep := fs.Bool("deep", false, "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) == 0 {
		return errors.New("sindook: rewrap takes at least one sealed file")
	}
	if *out != "" && len(inputs) > 1 {
		return errors.New("sindook: -o cannot be combined with multiple input files")
	}

	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "current passphrase")
	if err != nil {
		return err
	}
	opts, err := buildSealOptions(recipients, recipientFiles, *newPass, *newPassfile, "new passphrase")
	if err != nil {
		return err
	}

	if *out != "" {
		in, err := os.Open(inputs[0])
		if err != nil {
			return err
		}
		defer in.Close()
		return withOutput(*out, *force, true, func(w io.Writer) error {
			return rewrapStream(w, in, id, pass, opts, *deep)
		})
	}
	var errs []error
	for _, path := range inputs {
		if err := rewrapInPlace(path, id, pass, opts, *deep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rewrapStream rotates one sealed stream, preserving its encoding: armored
// input yields armored output.
func rewrapStream(w io.Writer, r io.Reader, id *xwing.PrivateKey, pass []byte, opts box.SealOptions, deep bool) error {
	src, armored, err := detectArmor(r)
	if err != nil {
		return err
	}
	if !armored {
		return box.Rewrap(w, src, id, pass, opts, deep)
	}
	aw := armor.NewWriter(w)
	if err := box.Rewrap(aw, src, id, pass, opts, deep); err != nil {
		return err
	}
	return aw.Close()
}

// rewrapInPlace writes the rewrapped file next to the original and renames
// it over the original only after a complete, successful write.
func rewrapInPlace(path string, id *xwing.PrivateKey, pass []byte, opts box.SealOptions, deep bool) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sindook-rewrap-*")
	if err != nil {
		return err
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	src := withProgress(in, info.Size(), "rewrap "+path)
	if err := rewrapStream(tmp, src, id, pass, opts, deep); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	return os.Rename(tmp.Name(), path)
}
