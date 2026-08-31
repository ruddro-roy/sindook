// Command sindook seals and opens files with post-quantum hybrid encryption.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/ruddro-roy/sindook/box"
	"github.com/ruddro-roy/sindook/internal/memguard"
)

const (
	skPrefix = "sindooksk1:"
	pkPrefix = "sindookpk1:"
	ext      = ".sindook"
)

// version is the source-tree development default. buildVersion resolves
// the reported version in this order: (1) a linker override via
// -X main.version, which release builds set to the exact tag; (2) the
// module version carried in the binary's build info when it is a real
// release tag, as produced by "go install ...@v0.7.1"; (3) this dev
// default, so source-tree builds stay visibly unreleased.
var version = "0.11.1-dev"

const usageMain = `sindook seals files with hybrid X25519 + ML-KEM-768 recipient slots
and can rotate access without decrypting or re-encrypting the payload in
fast mode. Fast rewrap still copies ciphertext to a replacement file.

usage: sindook <command> [flags] [FILE...]

  keygen      create an identity, optionally passphrase-protected
  init        create or select the explicit default identity
  pubkey      print the public key of an identity
  contacts    save and use named recipient public keys and groups
  config      inspect and change saved settings (default identity)
  paths       show the portable Sindook configuration locations
  seal        encrypt to recipients and/or a passphrase
  open        decrypt with an identity or passphrase
  verify      confirm sealed files decrypt cleanly, writing nothing
  inspect     show sealed-file metadata, no credentials needed
  rewrap      rotate recipients, passphrases, or the file key
  rotate      retire an old identity across many sealed files
  shred       overwrite and delete regular plaintext files
  scan        audit TLS endpoints and local keys for weak crypto
  selftest    run a fast built-in cryptographic sanity check
  doctor      diagnose the local installation and configuration
  completion  print a bash, zsh, fish, or PowerShell completion script
  version     print version and build provenance

"sindook help <command>" shows flags and examples.
`

var commands = map[string]struct {
	run   func([]string) error
	usage string
}{
	"keygen":     {cmdKeygen, usageKeygen},
	"init":       {cmdInit, usageInit},
	"pubkey":     {cmdPubkey, usagePubkey},
	"contacts":   {cmdContacts, usageContacts},
	"config":     {cmdConfig, usageConfig},
	"paths":      {cmdPaths, usagePaths},
	"seal":       {cmdSeal, usageSeal},
	"open":       {cmdOpen, usageOpen},
	"verify":     {cmdVerify, usageVerify},
	"inspect":    {cmdInspect, usageInspect},
	"rewrap":     {cmdRewrap, usageRewrap},
	"rotate":     {cmdRotate, usageRotate},
	"shred":      {cmdShred, usageShred},
	"scan":       {cmdScan, usageScan},
	"selftest":   {cmdSelftest, usageSelftest},
	"doctor":     {cmdDoctor, usageDoctor},
	"completion": {cmdCompletion, usageCompletion},
}

func main() {
	// Best-effort: keep key material from being paged out to swap. Failure
	// is reported by sindook doctor, never fatal.
	_ = memguard.LockAll()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageMain)
		os.Exit(2)
	}
	switch name := os.Args[1]; name {
	case "version", "-v", "--version":
		fmt.Println(buildVersion())
	case "help", "-h", "--help":
		if len(os.Args) > 2 {
			if cmd, ok := commands[os.Args[2]]; ok {
				fmt.Print(cmd.usage)
				return
			}
			fmt.Fprintf(os.Stderr, "sindook: unknown command %q\n\n%s", os.Args[2], usageMain)
			os.Exit(2)
		}
		fmt.Print(usageMain)
	default:
		cmd, ok := commands[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "sindook: unknown command %q\n\n%s", name, usageMain)
			os.Exit(2)
		}
		if err := cmd.run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCode(err))
		}
	}
}

// usageError marks a command-line usage mistake: a bad flag combination, a
// wrong number of positional arguments, or a malformed credential. It maps
// to exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// usagef builds a usage error with the standard sindook prefix.
func usagef(format string, args ...any) error {
	return &usageError{msg: "sindook: " + fmt.Sprintf(format, args...)}
}

// exitCode maps a command error to a scriptable exit code:
//
//	0 success
//	1 operational failure (IO errors, malformed files, config errors, ...)
//	2 usage errors (flag and positional-argument mistakes)
//	3 authentication failure (wrong key, missing or wrong credential,
//	  or a tampered header)
//
// A joined error takes the most specific class present: any usage error
// beats any authentication error, which beats plain operational failure.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return 2
	}
	if errors.Is(err, box.ErrWrongKey) ||
		errors.Is(err, box.ErrNeedIdentity) ||
		errors.Is(err, box.ErrNeedPassphrase) ||
		errors.Is(err, box.ErrHeaderTampered) {
		return 3
	}
	return 1
}

// newFlagSet builds a flag set whose -h and parse failures print the
// command's full usage text instead of the bare flag defaults.
func newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}
	return fs
}

// buildVersion appends VCS provenance when the binary was built from a
// checkout, so bug reports identify the exact commit.
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "sindook " + resolveVersion(version, nil)
	}
	v := "sindook " + resolveVersion(version, bi)
	var rev, at string
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			at = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return v
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	if at != "" {
		rev += ", " + at
	}
	return v + " (" + rev + ")"
}

func baseVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return resolveVersion(version, nil)
	}
	return resolveVersion(version, bi)
}

// releaseTagPattern matches module versions that are real release tags:
// major.minor.patch with an optional rc/beta/alpha/pre prerelease suffix,
// case-insensitive on the suffix. Pseudo-versions (v0.0.0-20240101...-abc)
// and "(devel)" deliberately do not match, so only tagged builds report a
// release version when no -X main.version override was supplied.
var releaseTagPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-(?i:rc|beta|alpha|pre)[0-9]*)?$`)

// resolveVersion picks the base version string for buildVersion. It is
// pure so tests can exercise the resolution table directly.
func resolveVersion(devDefault string, bi *debug.BuildInfo) string {
	if releaseTagPattern.MatchString(devDefault) {
		return strings.TrimPrefix(devDefault, "v")
	}
	if bi == nil || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return devDefault
	}
	if !releaseTagPattern.MatchString(bi.Main.Version) {
		return devDefault
	}
	return strings.TrimPrefix(bi.Main.Version, "v")
}
