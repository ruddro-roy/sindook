package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageRotate = `usage: sindook rotate -i IDENTITY [-identity-passfile FILE]
                       (-to RECIPIENT)... [-deep] [-jobs N]
                       [-glob PATTERN]... [-json] DIR|FILE...

Retire an identity from sealed files in bulk. Every candidate file is
opened with IDENTITY; files it opens are rewrapped to the -to
recipients, files it cannot open are reported as skipped. Use it when
one identity must lose access to everything: offboarding, a compromised
key, or a periodic hygiene pass. The identity being retired must be
held, because authenticated opening is what decides which files match;
the current format has no metadata filter.

Rotation replaces each file's slot set with exactly the -to recipients.
Fast mode keeps the payload ciphertext; -deep re-encrypts under a fresh
file key. Fast mode does not revoke recipients who already hold a copy
of the old file. Files are staged beside their original path and
replaced only after a successful write.

Directory operands are walked for *.sindook files; explicit FILE
operands are attempted whatever their name. Every file is attempted
even if an earlier one fails, and the exit code is non-zero only when a
rewrap failed; skipped files are not failures.

flags:
  -i IDENTITY     the identity being retired (required)
  -identity-passfile FILE
                  read a protected identity's passphrase from FILE
  -to RECIPIENT   new recipient, repeatable; the replacement file is
                  sealed to exactly these recipients
  -deep           re-encrypt the payload under a fresh file key
  -jobs N         rotate up to N files concurrently (default: up to 4
                  for multiple files, 1 for a single file)
  -glob PATTERN    add files matched by a portable filesystem pattern
  -json           print one machine-readable JSON array with per-file
                  status instead of human-readable lines

examples:
  sindook rotate -i old.key -to @team backups/
  sindook rotate -i offboarded.key -to personal.key.pub -deep -jobs 8 vault/
  sindook rotate -i old.key -to alice.pub -glob "archive/*.sindook"
`

// rotateResult is the per-file report row. The status vocabulary is
// rotated (sealed to the identity, rewrapped), skipped (the identity
// cannot open it, or the file is damaged), failed (the rewrap errored).
type rotateResult struct {
	File   string `json:"file"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func cmdRotate(args []string) error {
	fs := newFlagSet("rotate", usageRotate)
	idPath := fs.String("i", "", "")
	identityPassfile := fs.String("identity-passfile", "", "")
	var tos multiFlag
	fs.Var(&tos, "to", "")
	deep := fs.Bool("deep", false, "")
	jobs := fs.Int("jobs", 0, "")
	jsonOut := fs.Bool("json", false, "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	parseInterspersedFlags(fs, args)

	if *idPath == "" {
		return usagef("rotate requires -i IDENTITY, the identity being retired")
	}
	if len(tos) == 0 {
		return usagef("rotate needs at least one -to recipient for the replacement files")
	}
	if *jobs < 0 {
		return usagef("-jobs cannot be negative")
	}
	inputs, err := expandInputs(fs.Args(), globs)
	if err != nil {
		return err
	}
	files, err := collectRotateInputs(inputs)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usagef("rotate takes at least one sealed file or directory")
	}

	// loadCredentials never falls back to the default identity here,
	// because rotating away from an identity requires naming it.
	id, _, err := loadCredentials(*idPath, false, "", *identityPassfile, "passphrase")
	if err != nil {
		return err
	}
	defer id.Wipe()
	opts, err := buildSealOptions(tos, nil, false, "", "new passphrase")
	if err != nil {
		return err
	}

	workers := *jobs
	if workers > len(files) {
		workers = len(files)
	}
	if workers == 0 {
		workers = runtime.NumCPU()
		if workers > 4 {
			workers = 4
		}
	}
	if workers > 1 && len(files) < 2 {
		workers = 1
	}
	// The per-file progress meter redraws one stderr line; only a single
	// worker may draw it.
	progress := workers == 1

	results := make([]rotateResult, len(files))
	failErrs := make([]error, len(files))
	if workers <= 1 {
		for i, path := range files {
			results[i], failErrs[i] = rotateOne(path, id, opts, *deep, progress)
		}
	} else {
		tasks := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range tasks {
					results[i], failErrs[i] = rotateOne(files[i], id, opts, *deep, false)
				}
			}()
		}
		for i := range files {
			tasks <- i
		}
		close(tasks)
		wg.Wait()
	}

	var errs []error
	rotated, skipped, failed := 0, 0, 0
	for i, res := range results {
		switch res.Status {
		case "rotated":
			rotated++
		case "skipped":
			skipped++
		default:
			failed++
			errs = append(errs, fmt.Errorf("%s: %w", res.File, failErrs[i]))
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			errs = append(errs, err)
		}
	} else {
		for _, res := range results {
			switch res.Status {
			case "rotated":
				fmt.Printf("%s: rotated\n", res.File)
			case "skipped":
				fmt.Printf("%s: skipped (%s)\n", res.File, res.Error)
			default:
				fmt.Printf("%s: FAILED (%s)\n", res.File, res.Error)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Attempted %d, rotated %d, skipped %d, failed %d\n",
		len(results), rotated, skipped, failed)
	return errors.Join(errs...)
}

// collectRotateInputs resolves operands: directories are walked for
// *.sindook files, plain files pass through unchanged, and the result is
// sorted and deduplicated so the report order is stable.
func collectRotateInputs(inputs []string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	for _, in := range inputs {
		if in == "-" {
			return nil, usagef("rotate works on files, not stdin")
		}
		info, err := os.Stat(in)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(in)
			continue
		}
		err = filepath.WalkDir(in, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ext) {
				add(p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", in, err)
		}
	}
	sort.Strings(files)
	return files, nil
}

// isSkippable classifies attempt failures that mean "not this identity's
// file": wrong credential, a damaged or tampered file, or not a sindook
// file at all. Everything else (I/O) is an operational failure.
func isSkippable(err error) bool {
	return errors.Is(err, box.ErrWrongKey) ||
		errors.Is(err, box.ErrHeaderTampered) ||
		errors.Is(err, box.ErrPayloadCorrupted) ||
		errors.Is(err, box.ErrNotSindook)
}

// rotateOne attempts one file with the retired identity and, when it
// opens, rewraps it in place. The returned error is non-nil only for
// status failed, so it decides the exit code.
func rotateOne(path string, id *xwing.PrivateKey, opts box.SealOptions, deep, progress bool) (rotateResult, error) {
	res := rotateResult{File: path}
	err := attemptOpen(path, id, progress)
	if err == nil {
		if err := rewrapInPlace(path, id, nil, opts, deep, progress); err != nil {
			res.Status = "failed"
			res.Error = err.Error()
			return res, err
		}
		res.Status = "rotated"
		return res, nil
	}
	if isSkippable(err) {
		res.Status = "skipped"
		res.Error = err.Error()
		return res, nil
	}
	res.Status = "failed"
	res.Error = err.Error()
	return res, err
}

// attemptOpen reports whether path opens with id, decrypting to
// io.Discard so no plaintext is written anywhere.
func attemptOpen(path string, id *xwing.PrivateKey, progress bool) error {
	in, _, size, err := openInput(path)
	if err != nil {
		return err
	}
	defer in.Close()
	var src io.Reader = in
	if progress {
		src = withProgress(in, size, "rotate "+path)
	}
	src, _, err = detectArmor(src)
	if err != nil {
		return err
	}
	return box.Open(io.Discard, src, id, nil)
}
