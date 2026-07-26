package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ruddro-roy/sindook/internal/box"
)

const usageMigrate = `usage: sindook migrate (-i IDENTITY | -p | -passfile FILE)
                       [-r RECIPIENT]... [-R FILE]...
                       [-new-passphrase | -new-passfile FILE]
                       [-header-capacity BYTES] [-reserve N] [-json] FILE...

Convert sealed files to format v3, which reserves a fixed header arena so
every later rotation rewrites only the header. Payload ciphertext is copied
byte for byte and never decrypted, so the content key does not change and
anyone holding an old copy is exactly as able to read it as before.

This is a full-file rewrite, paid once per file. Permissions and
modification time are preserved. Already-v3 files are left alone unless a
different capacity is requested.

A sealed file does not record who its recipients are, so migrating a file
with recipient slots needs the new recipient list. A passphrase-only file
reuses the passphrase that opened it.

flags:
  -i IDENTITY            identity that opens the files today
  -p                     open with the current passphrase (prompted)
  -passfile FILE         read the current passphrase from FILE
  -r RECIPIENT           recipient for the migrated file, repeatable
  -R FILE                file of recipients, one key per line, repeatable
  -new-passphrase        add a passphrase slot (prompted)
  -new-passfile FILE     read the new passphrase from FILE
  -header-capacity BYTES exact arena slot size, multiple of 4096
  -reserve N             room for N more recipients later (default 4)
  -json                  print one JSON record per migrated file

examples:
  sindook migrate -i my.key -r my.key.pub archive.tar.sindook
  sindook migrate -p notes.txt.sindook
  sindook migrate -i my.key -R team.keys -reserve 16 backups/*.sindook
`

func cmdMigrate(args []string) error {
	fs := newFlagSet("migrate", usageMigrate)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	var recipients, recipientFiles multiFlag
	fs.Var(&recipients, "r", "")
	fs.Var(&recipientFiles, "R", "")
	newPass := fs.Bool("new-passphrase", false, "")
	newPassfile := fs.String("new-passfile", "", "")
	capacity := fs.Int("header-capacity", 0, "")
	reserve := fs.Int("reserve", -1, "")
	jsonOut := fs.Bool("json", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) == 0 {
		return errors.New("sindook: migrate takes at least one sealed file")
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "current passphrase")
	if err != nil {
		return err
	}
	// An empty slot set is allowed here: migrateStream reuses the opening
	// passphrase for passphrase-only files and refuses to guess otherwise.
	opts, err := buildOptionalSealOptions(recipients, recipientFiles, *newPass, *newPassfile)
	if err != nil {
		return err
	}
	arena, err := arenaOptions(*capacity, *reserve)
	if err != nil {
		return err
	}

	var errs []error
	results := []*box.MigrateResult{}
	for _, path := range inputs {
		skip, err := alreadyMigrated(path, *capacity)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if skip {
			fmt.Fprintf(os.Stderr, "%s: already format v3, unchanged\n", path)
			continue
		}
		res, err := box.MigrateFile(context.Background(), path, id, pass, opts, arena)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, res)
		if !*jsonOut {
			fmt.Printf("%s: v%d to v3, arena %s per slot, %d key slot(s), %s payload copied\n",
				res.Path, res.FromVersion, humanBytes(int64(res.SlotCapacity)),
				res.KeySlots, humanBytes(res.BytesCopied))
		}
	}
	if *jsonOut {
		if err := printJSON(results); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// alreadyMigrated reports whether path is a v3 file that does not need to be
// rewritten. A different requested capacity is a reason to rewrite it.
func alreadyMigrated(path string, wantCapacity int) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	v, err := box.FileVersion(f)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	if v != 3 {
		return false, nil
	}
	if wantCapacity == 0 {
		return true, nil
	}
	info, err := box.InspectAt(f)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return info.Arena.SlotCapacity == uint32(wantCapacity), nil
}

const usageRepair = `usage: sindook repair (-i IDENTITY | -p | -passfile FILE) [-json] FILE...

Finish a rotation that was interrupted. A crash between the two header
commits can leave both the old and the new policy present in the arena;
until the scrub completes, the superseded policy is still recoverable.
Repair rewrites the authoritative header into both slots, after which no
superseded key material remains anywhere in the arena.

Files that are already consistent are reported and left alone. This
changes neither the policy nor the generation.

flags:
  -i IDENTITY     identity that opens the files
  -p              open with a passphrase (prompted)
  -passfile FILE  read the passphrase from FILE
  -json           print one JSON record per file

example:
  sindook repair -i my.key archive.tar.sindook
`

func cmdRepair(args []string) error {
	fs := newFlagSet("repair", usageRepair)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	jsonOut := fs.Bool("json", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) == 0 {
		return errors.New("sindook: repair takes at least one sealed file")
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "passphrase")
	if err != nil {
		return err
	}

	var errs []error
	results := []*box.RewrapResult{}
	for _, path := range inputs {
		res, err := box.RepairFile(context.Background(), path, id, pass)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, res)
		if !*jsonOut {
			what := "already consistent"
			if res.BytesWritten > 0 {
				what = fmt.Sprintf("scrubbed, %s rewritten", humanBytes(res.BytesWritten))
			}
			fmt.Printf("%s: generation %d, %s\n", path, res.Generation, what)
		}
	}
	if *jsonOut {
		if err := printJSON(results); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

const usageRecover = `usage: sindook recover (-i IDENTITY | -p | -passfile FILE) [-o OUT] [-f] FILE

Open a superseded header generation.

A normal open uses only the current generation, and never falls back to an
older one when a credential fails: falling back would hand access back to
an identity that was just removed. After an interrupted rotation the
previous generation may still be physically present, and this command is
the only way to read it.

Use it to recover data after a rotation went wrong, then run
"sindook repair" to complete the scrub. Reading a superseded generation
means an identity that was removed can still open this file, which is
exactly the state repair exists to end.

flags:
  -i IDENTITY     identity to try
  -p              open with a passphrase (prompted)
  -passfile FILE  read the passphrase from FILE
  -o OUT          output path, - for stdout
  -f              overwrite existing output

example:
  sindook recover -i old.key -o rescued.tar archive.tar.sindook
`

func cmdRecover(args []string) error {
	fs := newFlagSet("recover", usageRecover)
	idPath := fs.String("i", "", "")
	usePass := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	out := fs.String("o", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) != 1 {
		return errors.New("sindook: recover takes exactly one sealed file")
	}
	id, pass, err := loadCredentials(*idPath, *usePass, *passfile, "passphrase")
	if err != nil {
		return err
	}

	f, err := os.Open(inputs[0])
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	outPath := *out
	if outPath == "" {
		if !strings.HasSuffix(inputs[0], ext) {
			return fmt.Errorf("sindook: %s does not end in %s, use -o", inputs[0], ext)
		}
		outPath = strings.TrimSuffix(inputs[0], ext)
	}
	fmt.Fprintf(os.Stderr, "sindook: reading a superseded generation of %s; an identity removed by the last rotation may open it\n", inputs[0])
	return withOutput(outPath, *force, false, func(w io.Writer) error {
		return box.OpenAt(context.Background(), f, info.Size(), w, id, pass, true)
	})
}
