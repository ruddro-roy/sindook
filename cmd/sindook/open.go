package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/internal/armor"
	"github.com/ruddro-roy/sindook/internal/baseline"
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
                      [-glob PATTERN]... [-json] [-jobs N]
                      [-save BASELINE | -baseline BASELINE] [FILE...]

Fully decrypt and authenticate sealed files without writing plaintext
anywhere. Confirms a backup will actually open before you need it. Every
file is checked even if an earlier one fails; the exit code is non-zero if
any did. With no credential flag, the identity selected by sindook init is
used when one exists. With -z, the gzip stream is also decompressed in
memory, confirming a compressed archive is fully recoverable.

Baselines record restorability over time: -save writes every successfully
verified file (path, sealed-file SHA-256, size, timestamp) to a JSON
baseline. A later run with -baseline compares against it and reports
unchanged files, files whose sealed bytes changed, new files, and baseline
entries missing from disk. With -baseline and no FILE operands, the
baseline's own file list is verified. Baseline drift is reported but only
failed decryption changes the exit code.

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
  -jobs N         verify up to N files concurrently (default: up to 4
                  for multiple files, 1 for a single file or stdin;
                  per-file progress is shown only in single-job runs)
  -json            print one machine-readable JSON array with per-file
                  status instead of human-readable ok/FAILED lines
  -save BASELINE   write a JSON baseline of verified files
  -baseline BASELINE
                  compare results against a baseline written by -save

example:
  sindook verify -z -i my.key backups/*.sindook
`

type verifyResult struct {
	File           string `json:"file"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Size           *int64 `json:"size,omitempty"`
	BaselineSHA256 string `json:"baseline_sha256,omitempty"`
}

// verifyOutcome pairs a per-file report with the error that decides the
// exit code; failErr is nil unless decryption itself failed.
type verifyOutcome struct {
	res     verifyResult
	failErr error
}

// loadBaseline reads and validates a baseline file written by -save.
func loadBaseline(path string) (baseline.Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return baseline.Record{}, err
	}
	return baseline.Parse(raw, path)
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
	jobs := fs.Int("jobs", 0, "")
	savePath := fs.String("save", "", "")
	baselinePath := fs.String("baseline", "", "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	parseInterspersedFlags(fs, args)

	if *savePath != "" && *baselinePath != "" {
		return usagef("-save and -baseline cannot be combined")
	}
	if *jobs < 0 {
		return usagef("-jobs cannot be negative")
	}
	wantHash := *savePath != "" || *baselinePath != ""

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
	var record baseline.Record
	var baselineIndex map[string]baseline.Entry
	if *baselinePath != "" {
		record, err = loadBaseline(*baselinePath)
		if err != nil {
			return err
		}
		baselineIndex = make(map[string]baseline.Entry, len(record.Entries))
		for _, e := range record.Entries {
			baselineIndex[e.File] = e
		}
		// A bare -baseline run re-verifies exactly the recorded file set.
		if len(inputs) == 0 && len(globs) == 0 {
			for _, e := range record.Entries {
				inputs = append(inputs, e.File)
			}
		}
	}
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}

	workers := *jobs
	if workers > len(inputs) {
		workers = len(inputs)
	}
	if workers == 0 {
		workers = runtime.NumCPU()
		if workers > 4 {
			workers = 4
		}
	}
	if workers > 1 {
		for _, in := range inputs {
			if in == "-" {
				workers = 1 // one stdin stream cannot be read concurrently
				break
			}
		}
		if len(inputs) < 2 {
			workers = 1
		}
	}
	// The per-file progress meter redraws one stderr line; only a single
	// worker may draw it.
	progress := workers == 1

	outcomes := make([]verifyOutcome, len(inputs))
	if workers <= 1 {
		for i, inPath := range inputs {
			outcomes[i] = classifyOne(inPath, id, pass, *decompress, limit, wantHash, baselineIndex, progress)
		}
	} else {
		tasks := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range tasks {
					outcomes[i] = classifyOne(inputs[i], id, pass, *decompress, limit, wantHash, baselineIndex, false)
				}
			}()
		}
		for i := range inputs {
			tasks <- i
		}
		close(tasks)
		wg.Wait()
	}

	var errs []error
	checked := make(map[string]bool, len(inputs))
	results := make([]verifyResult, 0, len(inputs))
	for _, o := range outcomes {
		if o.failErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", o.res.File, o.failErr))
		}
		if baselineIndex != nil {
			checked[o.res.File] = true
		}
		results = append(results, o.res)
	}
	if baselineIndex != nil {
		for _, e := range record.Entries {
			if checked[e.File] {
				continue
			}
			results = append(results, verifyResult{
				File:           e.File,
				Status:         "missing",
				Error:          "in baseline but not found or not checked",
				BaselineSHA256: e.SHA256,
			})
		}
	}
	if *savePath != "" {
		now := time.Now().UTC().Format(time.RFC3339)
		baselineOut := baseline.Record{Version: baseline.Version, CreatedAt: now}
		for _, res := range results {
			if res.Status != "ok" {
				continue
			}
			baselineOut.Entries = append(baselineOut.Entries, baseline.Entry{
				File: res.File, SHA256: res.SHA256, Size: res.Size, VerifiedAt: now,
			})
		}
		raw, err := json.MarshalIndent(baselineOut, "", "  ")
		if err != nil {
			errs = append(errs, err)
		} else if err := writeOutputStaged(*savePath, 0o600, func(w io.Writer) error {
			_, err := w.Write(append(raw, '\n'))
			return err
		}); err != nil {
			errs = append(errs, err)
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
			case "ok":
				if res.BaselineSHA256 != "" {
					fmt.Printf("%s: ok (unchanged)\n", res.File)
				} else {
					fmt.Printf("%s: ok\n", res.File)
				}
			case "changed":
				fmt.Printf("%s: CHANGED since baseline\n", res.File)
			case "new":
				fmt.Printf("%s: new (not in baseline)\n", res.File)
			case "missing":
				fmt.Printf("%s: MISSING (in baseline)\n", res.File)
			default:
				fmt.Printf("%s: FAILED\n", res.File)
			}
		}
	}
	return errors.Join(errs...)
}

// classifyOne verifies one file and classifies the result against the
// baseline index (nil when not comparing). progress enables the per-file
// stderr meter; it is only safe from a single worker.
func classifyOne(inPath string, id *xwing.PrivateKey, pass []byte, decompress bool, maxDecompressed int64, wantHash bool, baselineIndex map[string]baseline.Entry, progress bool) verifyOutcome {
	name, sum, size, err := verifyOne(inPath, id, pass, decompress, maxDecompressed, wantHash, progress)
	out := verifyOutcome{res: verifyResult{File: name}}
	if wantHash {
		out.res.SHA256 = sum
		if size >= 0 {
			out.res.Size = &size
		}
	}
	if err != nil {
		out.res.Status = "failed"
		out.res.Error = err.Error()
		out.res.BaselineSHA256 = baselineIndex[name].SHA256
		// A baseline entry absent from disk is drift, not a decryption
		// failure: report it as missing without changing the exit code.
		if baselineIndex != nil && errors.Is(err, os.ErrNotExist) {
			if _, inBase := baselineIndex[name]; inBase {
				out.res.Status = "missing"
				out.res.Error = "in baseline but not found on disk"
				out.res.SHA256 = ""
				out.res.Size = nil
			}
		}
		if out.res.Status == "failed" {
			out.failErr = err
		}
		return out
	}
	if baselineIndex != nil {
		if entry, ok := baselineIndex[name]; !ok {
			out.res.Status = "new"
		} else {
			out.res.BaselineSHA256 = entry.SHA256
			if entry.SHA256 == sum {
				out.res.Status = "ok"
			} else {
				out.res.Status = "changed"
			}
		}
	} else {
		out.res.Status = "ok"
	}
	return out
}

func verifyOne(inPath string, id *xwing.PrivateKey, pass []byte, decompress bool, maxDecompressed int64, withHash bool, progress bool) (string, string, int64, error) {
	name := inPath
	if name == "" || name == "-" {
		name = "stdin"
	}
	in, _, size, err := openInput(inPath)
	if err != nil {
		return name, "", -1, err
	}
	defer in.Close()
	var src io.Reader = in
	if progress {
		src = withProgress(in, size, "verify "+name)
	}
	src, _, err = detectArmor(src)
	if err != nil {
		return name, "", -1, err
	}
	var digest hash.Hash
	if withHash {
		digest = sha256.New()
		src = io.TeeReader(src, digest)
	}
	open := func(w io.Writer) error {
		return box.Open(w, src, id, pass)
	}
	if decompress {
		open = func(w io.Writer) error {
			return withDecompression(w, maxDecompressed, func(dw io.Writer) error {
				return box.Open(dw, src, id, pass)
			})
		}
	}
	if err := open(io.Discard); err != nil {
		return name, "", -1, err
	}
	sum := ""
	if digest != nil {
		sum = hex.EncodeToString(digest.Sum(nil))
	}
	return name, sum, size, nil
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
