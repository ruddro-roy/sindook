// Command sindook seals and opens files with post-quantum hybrid encryption.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/internal/xwing"
)

const (
	version  = "0.1.0"
	skPrefix = "sindooksk1:"
	pkPrefix = "sindookpk1:"
	ext      = ".sindook"
)

const usageText = `sindook: post-quantum file encryption (X25519 + ML-KEM-768)

usage:
  sindook keygen [-o FILE] [-f]
  sindook seal (-r RECIPIENT | -p) [-o OUT] [-f] [FILE]
  sindook open (-i IDENTITY | -p) [-o OUT] [-f] [FILE]
  sindook version

FILE defaults to stdin, OUT then defaults to stdout.
seal writes FILE` + ext + `, open strips the suffix.
RECIPIENT is a path to a key file or a literal ` + pkPrefix + ` string.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "seal":
		err = cmdSeal(os.Args[2:])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "sindook: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "sindook.key", "identity file to write")
	force := fs.Bool("f", false, "overwrite existing files")
	fs.Parse(args)
	if fs.NArg() != 0 {
		return errors.New("sindook: keygen takes no positional arguments")
	}
	k, err := xwing.GenerateKey()
	if err != nil {
		return err
	}
	pub := pkPrefix + base64.RawStdEncoding.EncodeToString(k.PublicKey())
	id := fmt.Sprintf("# sindook identity, created %s\n# public: %s\n%s%s\n",
		time.Now().UTC().Format(time.RFC3339), pub,
		skPrefix, base64.RawStdEncoding.EncodeToString(k.Seed()))
	if err := writeFileNew(*out, []byte(id), 0o600, *force); err != nil {
		return err
	}
	if err := writeFileNew(*out+".pub", []byte(pub+"\n"), 0o644, *force); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "identity: %s\npublic key: %s\n", *out, *out+".pub")
	fmt.Println(pub)
	return nil
}

func cmdSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	rec := fs.String("r", "", "recipient key file or literal public key")
	usePass := fs.Bool("p", false, "seal with a passphrase")
	out := fs.String("o", "", "output path, - for stdout")
	force := fs.Bool("f", false, "overwrite existing output")
	fs.Parse(args)
	if fs.NArg() > 1 {
		return errors.New("sindook: seal takes at most one input file")
	}
	if (*rec != "") == *usePass {
		return errors.New("sindook: choose exactly one of -r or -p")
	}

	in, name, err := openInput(fs.Arg(0))
	if err != nil {
		return err
	}
	defer in.Close()

	var sealFn func(io.Writer) error
	if *rec != "" {
		pub, err := loadRecipient(*rec)
		if err != nil {
			return err
		}
		sealFn = func(w io.Writer) error { return box.SealRecipient(w, in, pub) }
	} else {
		pass, err := promptPassphrase(true)
		if err != nil {
			return err
		}
		sealFn = func(w io.Writer) error { return box.SealPassphrase(w, in, pass, box.DefaultArgon2id) }
	}

	outPath := *out
	if outPath == "" {
		if name == "" {
			outPath = "-"
		} else {
			outPath = name + ext
		}
	}
	return withOutput(outPath, *force, true, sealFn)
}

func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	idPath := fs.String("i", "", "identity file")
	usePass := fs.Bool("p", false, "open with a passphrase")
	out := fs.String("o", "", "output path, - for stdout")
	force := fs.Bool("f", false, "overwrite existing output")
	fs.Parse(args)
	if fs.NArg() > 1 {
		return errors.New("sindook: open takes at most one input file")
	}
	if *idPath == "" && !*usePass {
		return errors.New("sindook: provide -i IDENTITY or -p")
	}

	var id *xwing.PrivateKey
	if *idPath != "" {
		var err error
		if id, err = loadIdentity(*idPath); err != nil {
			return err
		}
	}
	var pass []byte
	if *usePass {
		var err error
		if pass, err = promptPassphrase(false); err != nil {
			return err
		}
	}

	in, name, err := openInput(fs.Arg(0))
	if err != nil {
		return err
	}
	defer in.Close()

	outPath := *out
	if outPath == "" {
		switch {
		case name == "":
			outPath = "-"
		case strings.HasSuffix(name, ext):
			outPath = strings.TrimSuffix(name, ext)
		default:
			return errors.New("sindook: input does not end in " + ext + ", use -o")
		}
	}
	return withOutput(outPath, *force, false, func(w io.Writer) error {
		return box.Open(w, in, id, pass)
	})
}

func openInput(arg string) (io.ReadCloser, string, error) {
	if arg == "" || arg == "-" {
		return os.Stdin, "", nil
	}
	f, err := os.Open(arg)
	if err != nil {
		return nil, "", err
	}
	return f, arg, nil
}

// withOutput creates path (refusing to clobber without force), runs fn, and
// removes the partial file if fn fails. binaryGuard refuses to stream
// ciphertext onto an interactive terminal.
func withOutput(path string, force, binaryGuard bool, fn func(io.Writer) error) error {
	if path == "-" {
		if binaryGuard && term.IsTerminal(int(os.Stdout.Fd())) {
			return errors.New("sindook: refusing to write ciphertext to a terminal, use -o")
		}
		return fn(os.Stdout)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func writeFileNew(path string, data []byte, perm os.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func loadIdentity(path string) (*xwing.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, skPrefix) {
			continue
		}
		seed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, skPrefix))
		if err != nil || len(seed) != xwing.SeedSize {
			return nil, fmt.Errorf("sindook: malformed identity in %s", path)
		}
		return xwing.NewPrivateKey(seed)
	}
	return nil, fmt.Errorf("sindook: no %s entry in %s", skPrefix, path)
}

// loadRecipient accepts a literal public key string, a .pub file, or an
// identity file (which carries its public key on a "# public:" line).
func loadRecipient(s string) ([]byte, error) {
	b64 := ""
	if strings.HasPrefix(s, pkPrefix) {
		b64 = strings.TrimPrefix(s, pkPrefix)
	} else {
		raw, err := os.ReadFile(s)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimSpace(strings.TrimPrefix(line, "# public:"))
			if strings.HasPrefix(line, pkPrefix) {
				b64 = strings.TrimPrefix(line, pkPrefix)
				break
			}
		}
		if b64 == "" {
			return nil, fmt.Errorf("sindook: no %s entry in %s", pkPrefix, s)
		}
	}
	pub, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(pub) != xwing.PublicKeySize {
		return nil, errors.New("sindook: malformed recipient public key")
	}
	return pub, nil
}

func promptPassphrase(confirm bool) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errors.New("sindook: no terminal available for the passphrase prompt")
		}
		tty = os.Stdin
	} else {
		defer tty.Close()
	}
	fmt.Fprint(os.Stderr, "passphrase: ")
	p1, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(p1) == 0 {
		return nil, errors.New("sindook: empty passphrase")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "confirm: ")
		p2, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(p1, p2) {
			return nil, errors.New("sindook: passphrases do not match")
		}
	}
	return p1, nil
}
