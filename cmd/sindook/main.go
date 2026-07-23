// Command sindook seals and opens files with post-quantum hybrid encryption.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

const (
	version  = "0.4.0"
	skPrefix = "sindooksk1:"
	pkPrefix = "sindookpk1:"
	ext      = ".sindook"
)

const usageMain = `sindook seals files so ciphertext recorded today stays sealed against a
quantum computer later (X25519 + ML-KEM-768), and rotates access across
any amount of data without re-encrypting it.

usage: sindook <command> [flags] [FILE...]

  keygen      create an identity, optionally passphrase-protected
  pubkey      print the public key of an identity
  seal        encrypt to recipients and/or a passphrase
  open        decrypt with an identity or passphrase
  verify      confirm sealed files decrypt cleanly, writing nothing
  inspect     show sealed-file metadata, no credentials needed
  rewrap      rotate recipients, passphrases, or the file key
  completion  print a bash, zsh, or fish completion script
  version     print version and build provenance

"sindook help <command>" shows flags and examples.
`

var commands = map[string]struct {
	run   func([]string) error
	usage string
}{
	"keygen":     {cmdKeygen, usageKeygen},
	"pubkey":     {cmdPubkey, usagePubkey},
	"seal":       {cmdSeal, usageSeal},
	"open":       {cmdOpen, usageOpen},
	"verify":     {cmdVerify, usageVerify},
	"inspect":    {cmdInspect, usageInspect},
	"rewrap":     {cmdRewrap, usageRewrap},
	"completion": {cmdCompletion, usageCompletion},
}

func main() {
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
			os.Exit(1)
		}
	}
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
	v := "sindook " + version
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
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
