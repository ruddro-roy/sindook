package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/memguard"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageRewrap = `usage: sindook rewrap [-i IDENTITY | -p | -passfile FILE]
                      [-identity-passfile FILE]
                      [-keep] [-drop-slot N]... [-drop-i IDENTITY]...
                      [-drop-p] [-drop-passfile FILE]... [-drop-pass-slots]
                      [-r RECIPIENT]... [-R FILE]...
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

By default the replacement slot set is exactly the -r/-R/-new-* arguments.
With -keep the existing slots are preserved and those arguments append to
them; the -drop-* flags remove matching slots from the kept set and imply
-keep. Slot numbers are the ones sindook inspect prints. Every -drop-*
selector must match at least one slot, and an edit may not leave a file
with no slots. -deep cannot be combined with -keep or -drop-*: a fresh
file key and nonce invalidate every kept slot.

flags:
  -i IDENTITY         identity that opens the files today
                      use @default for the identity selected by sindook init
  -p                  open with the current passphrase (prompted)
  -passfile FILE      read the current passphrase from FILE
  -identity-passfile FILE
                      read a protected identity's passphrase from FILE
                      (applies to -i and -drop-i files alike)
  -keep               preserve existing key slots; drops and additions
                      apply on top of them
  -drop-slot N        drop slot N as listed by sindook inspect, repeatable
  -drop-i IDENTITY    drop every slot that opens under IDENTITY, repeatable
  -drop-p             drop every slot that opens under a prompted passphrase
  -drop-passfile FILE
                      drop every slot that opens under the passphrase in
                      FILE, repeatable
  -drop-pass-slots    drop every passphrase slot
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
  sindook rewrap -i my.key -keep -r carol.pub shared.sindook
  sindook rewrap -i my.key -drop-slot 2 shared.sindook
  sindook rewrap -i my.key -drop-i old.key -r new.pub *.sindook
  sindook rewrap -i my.key -drop-pass-slots recipients-only.sindook
  sindook rewrap -i my.key -r alice.pub -deep archive.tar.sindook
`

func cmdRewrap(args []string) error {
	fs := newFlagSet("rewrap", usageRewrap)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	identityPassfile := fs.String("identity-passfile", "", "")
	keep := fs.Bool("keep", false, "")
	var dropSlots, dropIDs, dropPassfiles multiFlag
	fs.Var(&dropSlots, "drop-slot", "")
	fs.Var(&dropIDs, "drop-i", "")
	fs.Var(&dropPassfiles, "drop-passfile", "")
	dropPass := fs.Bool("drop-p", false, "")
	dropPassSlots := fs.Bool("drop-pass-slots", false, "")
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

	incremental := *keep || len(dropSlots) > 0 || len(dropIDs) > 0 ||
		*dropPass || len(dropPassfiles) > 0 || *dropPassSlots
	if incremental && *deep {
		return usagef("-keep and -drop-* flags cannot be combined with -deep")
	}
	hasAdds := len(recipients) > 0 || len(recipientFiles) > 0 || *newPass || *newPassfile != ""
	if !incremental && !hasAdds {
		return usagef("rewrap needs at least one new recipient (-r), recipient file (-R), or -new-passphrase; -keep edits the existing slots instead")
	}
	var opts box.SealOptions
	if hasAdds {
		opts, err = buildSealOptions(recipients, recipientFiles, *newPass, *newPassfile, "new passphrase")
		if err != nil {
			return err
		}
		defer wipePassphrases(&opts)
	}

	var edit *box.SlotEdit
	if incremental {
		e := box.SlotEdit{KeepAll: true, Add: opts}
		for _, s := range dropSlots {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				return usagef("invalid -drop-slot %q: slot numbers are positive integers as listed by sindook inspect", s)
			}
			e.DropSlots = append(e.DropSlots, n)
		}
		e.DropPassSlots = *dropPassSlots
		for _, p := range dropIDs {
			d, err := loadIdentityWithPassfile(p, *identityPassfile)
			if err != nil {
				return err
			}
			e.DropIdentities = append(e.DropIdentities, d)
		}
		defer func() {
			for _, d := range e.DropIdentities {
				d.Wipe()
			}
		}()
		if *dropPass {
			q, err := getPassphrase("", "passphrase of slot to drop", false)
			if err != nil {
				return err
			}
			e.DropPassphrases = append(e.DropPassphrases, q)
		}
		for _, f := range dropPassfiles {
			q, err := readPassfile(f)
			if err != nil {
				return err
			}
			e.DropPassphrases = append(e.DropPassphrases, q)
		}
		defer func() {
			for _, q := range e.DropPassphrases {
				memguard.Wipe(q)
			}
		}()
		edit = &e
	}
	op := rewrapOp{id: id, pass: pass, opts: opts, edit: edit, deep: *deep}

	if *out != "" {
		in, err := os.Open(inputs[0])
		if err != nil {
			return err
		}
		defer in.Close()
		return withOutput(*out, *force, true, func(w io.Writer) error {
			return rewrapStream(w, in, op)
		})
	}
	var errs []error
	for _, path := range inputs {
		if err := rewrapInPlace(path, op, true); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rewrapOp bundles one rewrap operation: a full slot replacement (opts) or,
// when edit is non-nil, an incremental slot edit that ignores deep.
type rewrapOp struct {
	id   *xwing.PrivateKey
	pass []byte
	opts box.SealOptions
	edit *box.SlotEdit
	deep bool
}

// rewrapStream rotates one sealed stream, preserving its encoding: armored
// input yields armored output.
func rewrapStream(w io.Writer, r io.Reader, op rewrapOp) error {
	src, armored, err := detectArmor(r)
	if err != nil {
		return err
	}
	run := func(out io.Writer) error {
		if op.edit != nil {
			return box.RewrapEdit(out, src, op.id, op.pass, *op.edit)
		}
		return box.Rewrap(out, src, op.id, op.pass, op.opts, op.deep)
	}
	if !armored {
		return run(w)
	}
	aw := armor.NewWriter(w)
	if err := run(aw); err != nil {
		return err
	}
	return aw.Close()
}

// rewrapInPlace stages the rewrapped file next to the original and replaces
// the original only after a complete, successful write. progress enables the
// stderr meter and is only safe from a single worker (see cmdVerify).
func rewrapInPlace(path string, op rewrapOp, progress bool) error {
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
	if err := rewrapStream(tmp, src, op); err != nil {
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
