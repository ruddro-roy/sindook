package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/xwing"
)

// printJSON writes a machine-readable receipt array, the form a policy run or
// a CI job consumes.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

const usageRewrap = `usage: sindook rewrap (-i IDENTITY | -p | -passfile FILE)
                      (-r RECIPIENT)... [-R FILE]...
                      [-new-passphrase | -new-passfile FILE]
                      [-deep] [-o OUT] [-f] FILE...

Replace the key slots of sealed files. By default only the header is
rewritten: the payload ciphertext is neither decrypted nor re-encrypted,
so the cryptographic work is the same for a kilobyte or a terabyte and
plaintext never exists anywhere. On a v3 file the header is updated in
place and the payload bytes are never read; on older formats the payload
is copied verbatim, so file I/O still scales with size. Fast mode does not
retroactively revoke someone who kept a copy of the old file; -deep
re-encrypts the payload under a fresh key and does. Rotating a whole
directory of files in one run is the intended use.

flags:
  -i IDENTITY         identity that opens the files today
  -p                  open with the current passphrase (prompted)
  -passfile FILE      read the current passphrase from FILE
  -r RECIPIENT        new recipient, repeatable
  -R FILE             file of new recipients, one key per line, repeatable
  -new-passphrase     add a new passphrase slot (prompted)
  -new-passfile FILE  read the new passphrase from FILE
  -deep               re-encrypt the payload under a fresh file key
  -expect-generation N  fail unless the file is at generation N (v3 only)
  -json               print one JSON audit receipt per file
  -o OUT              output path, - for stdout (single FILE only)
  -f                  overwrite existing output

examples:
  sindook rewrap -i my.key -r alice.pub -r bob.pub archive.tar.sindook
  sindook rewrap -i my.key -r alice.pub -deep archive.tar.sindook
  sindook rewrap -i old.key -R team.keys -json backups/*.sindook
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
	expectGen := fs.Uint64("expect-generation", 0, "")
	jsonOut := fs.Bool("json", false, "")
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
	if *expectGen != 0 && len(inputs) > 1 {
		return errors.New("sindook: -expect-generation describes one file, so it cannot be combined with multiple input files")
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
	receipts := []*box.RewrapResult{}
	for _, path := range inputs {
		res, err := rewrapOne(path, id, pass, opts, *deep, *expectGen)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if res != nil {
			receipts = append(receipts, res)
		}
	}
	if *jsonOut {
		if err := printJSON(receipts); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rewrapOne prefers the bounded in-place path. It applies to a v3 file whose
// payload is not being re-encrypted, which is the case the format exists for;
// everything else falls back to rewriting the file through a stream.
func rewrapOne(path string, id *xwing.PrivateKey, pass []byte, opts box.SealOptions, deep bool, expectGen uint64) (*box.RewrapResult, error) {
	if !deep {
		bounded, err := isBoundedRotatable(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if bounded {
			return box.RewrapFile(context.Background(), path, id, pass,
				box.RewrapAtOptions{Seal: opts, ExpectGeneration: expectGen})
		}
	}
	if expectGen != 0 {
		return nil, fmt.Errorf("%s: -expect-generation needs a format v3 file rotated in place; run sindook migrate first", path)
	}
	return nil, rewrapInPlace(path, id, pass, opts, deep)
}

// isBoundedRotatable reports whether path is a plain, unarmored v3 file. An
// armored file has no fixed offsets to write into, so it takes the stream
// path and comes back armored.
func isBoundedRotatable(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	v, err := box.FileVersion(f)
	if err != nil {
		return false, nil // not a bare sindook file: let the stream path report why
	}
	return v == 3, nil
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
