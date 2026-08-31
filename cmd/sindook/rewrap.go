package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/memguard"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageRewrap = `usage: sindook rewrap [-i IDENTITY | -p | -passfile FILE]
                      [-identity-passfile FILE]
                      (-r RECIPIENT)... [-R FILE]...
                      [-new-passphrase | -new-passfile FILE]
                      [-glob PATTERN]... [-deep] [-o OUT] [-f] FILE...

Replace the key slots of sealed files. With no unlocking credential flag,
the identity selected by sindook init is used when one exists. By default
fast mode preserves the payload ciphertext without decrypting or
re-encrypting it, then copies that ciphertext to a replacement file with a
fresh header. Fast mode does not revoke someone who kept a copy of the old
file. -deep creates a replacement with a fresh file key, so removed
recipients cannot open that replacement using the old file key. Files are
staged beside their original path and replaced only after a successful
write unless -o is given. Rotating a whole directory of files in one run
is the intended use.

flags:
  -i IDENTITY         identity that opens the files today
                      use @default for the identity selected by sindook init
  -p                  open with the current passphrase (prompted)
  -passfile FILE      read the current passphrase from FILE
  -identity-passfile FILE
                      read a protected identity's passphrase from FILE
  -r RECIPIENT        new recipient, repeatable
  -R FILE             file of new recipients, one key per line, repeatable
  -new-passphrase     add a new passphrase slot (prompted)
  -new-passfile FILE  read the new passphrase from FILE
  -glob PATTERN        add files matched by a portable filesystem pattern
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
	identityPassfile := fs.String("identity-passfile", "", "")
	var recipients, recipientFiles multiFlag
	fs.Var(&recipients, "r", "")
	fs.Var(&recipientFiles, "R", "")
	newPass := fs.Bool("new-passphrase", false, "")
	newPassfile := fs.String("new-passfile", "", "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	deep := fs.Bool("deep", false, "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	parseInterspersedFlags(fs, args)

	inputs, err := expandInputs(fs.Args(), globs)
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		return usagef("rewrap takes at least one sealed file")
	}
	if *out != "" && len(inputs) > 1 {
		return usagef("-o cannot be combined with multiple input files")
	}

	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, *identityPassfile, "current passphrase")
	if err != nil {
		return err
	}
	if id != nil {
		defer id.Wipe()
	}
	if pass != nil {
		defer memguard.Wipe(pass)
	}
	if len(recipients) == 0 && len(recipientFiles) == 0 && !*newPass && *newPassfile == "" {
		return usagef("rewrap needs at least one new recipient (-r), recipient file (-R), or -new-passphrase")
	}
	opts, err := buildSealOptions(recipients, recipientFiles, *newPass, *newPassfile, "new passphrase")
	if err != nil {
		return err
	}
	defer wipePassphrases(&opts)

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
		if err := rewrapInPlace(path, id, pass, opts, *deep, true); err != nil {
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

// rewrapInPlace stages the rewrapped file next to the original and replaces
// the original only after a complete, successful write. progress enables the
// stderr meter and is only safe from a single worker (see cmdVerify).
func rewrapInPlace(path string, id *xwing.PrivateKey, pass []byte, opts box.SealOptions, deep, progress bool) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sindook: refusing to rewrap symbolic link %s", path)
	}
	if !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("sindook: refusing to rewrap non-regular file %s", path)
	}

	in, err := os.Open(path)
	if err != nil {
		return err
	}
	inputOpen := true
	closeInput := func() error {
		if !inputOpen {
			return nil
		}
		inputOpen = false
		return in.Close()
	}
	defer closeInput()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, info) {
		return fmt.Errorf("sindook: input changed while preparing rewrap %s", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sindook-rewrap-*")
	if err != nil {
		return err
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	var src io.Reader = in
	if progress {
		src = withProgress(in, info.Size(), "rewrap "+path)
	}
	if err := rewrapStream(tmp, src, id, pass, opts, deep); err != nil {
		cleanup()
		return err
	}
	if err := closeInput(); err != nil {
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
	return replaceStaged(tmp.Name(), path)
}
