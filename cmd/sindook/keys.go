package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageKeygen = `usage: sindook keygen [-o FILE] [-p] [-passfile FILE] [-f]

Create a new identity. Writes FILE (secret, mode 0600) and FILE.pub
(shareable). With -p the identity file itself is sealed with a passphrase,
so a stolen key file alone cannot open anything; commands that use the
identity will prompt for the passphrase.

flags:
  -o FILE         identity file to write (default sindook.key)
  -p              protect the identity file with a passphrase
  -passfile FILE  read the protection passphrase from FILE, implies -p
  -f              overwrite existing files

examples:
  sindook keygen -o my.key
  sindook keygen -o my.key -p
`

func cmdKeygen(args []string) error {
	fs := newFlagSet("keygen", usageKeygen)
	out := fs.String("o", "sindook.key", "")
	protect := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	force := fs.Bool("f", false, "")
	fs.Parse(args)
	if fs.NArg() != 0 {
		return errors.New("sindook: keygen takes no positional arguments")
	}
	*protect = *protect || *passfile != ""

	k, err := xwing.GenerateKey()
	if err != nil {
		return err
	}
	pub := pkPrefix + base64.RawStdEncoding.EncodeToString(k.PublicKey())
	id := []byte(fmt.Sprintf("# sindook identity, created %s\n# public: %s\n%s%s\n",
		time.Now().UTC().Format(time.RFC3339), pub,
		skPrefix, base64.RawStdEncoding.EncodeToString(k.Seed())))

	if *protect {
		pass, err := getPassphrase(*passfile, "identity passphrase", true)
		if err != nil {
			return err
		}
		var sealed bytes.Buffer
		if err := box.SealPassphrase(&sealed, bytes.NewReader(id), pass, box.DefaultArgon2id); err != nil {
			return err
		}
		id = sealed.Bytes()
	}
	if err := writeFileNew(*out, id, 0o600, *force); err != nil {
		return err
	}
	if err := writeFileNew(*out+".pub", []byte(pub+"\n"), 0o644, *force); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "identity: %s\npublic key: %s\n", *out, *out+".pub")
	fmt.Println(pub)
	return nil
}

const usagePubkey = `usage: sindook pubkey [FILE]

Print the public key of an identity. FILE defaults to stdin. A
passphrase-protected identity prompts for its passphrase.

example:
  sindook pubkey my.key
`

func cmdPubkey(args []string) error {
	fs := newFlagSet("pubkey", usagePubkey)
	fs.Parse(args)
	if fs.NArg() > 1 {
		return errors.New("sindook: pubkey takes at most one identity file")
	}
	id, err := loadIdentity(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Println(pkPrefix + base64.RawStdEncoding.EncodeToString(id.PublicKey()))
	return nil
}

// loadIdentity reads an identity from a file or stdin ("" or "-"). A
// passphrase-protected identity, recognizable by the sindook magic, is
// decrypted after prompting at the terminal.
func loadIdentity(path string) (*xwing.PrivateKey, error) {
	var raw []byte
	var err error
	display := path
	if path == "" || path == "-" {
		display = "identity on stdin"
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("SINDOOK")) {
		pass, err := promptPassphrase("passphrase for "+display, false)
		if err != nil {
			return nil, err
		}
		if raw, err = openSealedIdentity(raw, pass); err != nil {
			return nil, err
		}
	}
	return parseIdentity(raw, display)
}

func openSealedIdentity(raw, pass []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := box.Open(&limitedWriter{w: &buf, n: 1 << 20}, bytes.NewReader(raw), nil, pass); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseIdentity(raw []byte, display string) (*xwing.PrivateKey, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, skPrefix) {
			continue
		}
		seed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, skPrefix))
		if err != nil || len(seed) != xwing.SeedSize {
			return nil, fmt.Errorf("sindook: malformed identity in %s", display)
		}
		return xwing.NewPrivateKey(seed)
	}
	return nil, fmt.Errorf("sindook: no %s entry in %s", skPrefix, display)
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
	return decodeRecipient(b64)
}

// loadRecipientsFile reads one public key per line; blank lines and #
// comments are skipped, so concatenated .pub files work as-is.
func loadRecipientsFile(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pubs [][]byte
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, pkPrefix) {
			return nil, fmt.Errorf("sindook: %s:%d: not a %s key", path, i+1, pkPrefix)
		}
		pub, err := decodeRecipient(strings.TrimPrefix(line, pkPrefix))
		if err != nil {
			return nil, fmt.Errorf("sindook: %s:%d: malformed public key", path, i+1)
		}
		pubs = append(pubs, pub)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("sindook: no recipients in %s", path)
	}
	return pubs, nil
}

func decodeRecipient(b64 string) ([]byte, error) {
	pub, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(pub) != xwing.PublicKeySize {
		return nil, errors.New("sindook: malformed recipient public key")
	}
	return pub, nil
}

// buildSealOptions loads every recipient and resolves the passphrase up
// front, so credential errors surface before any output is created.
func buildSealOptions(recipients, recipientFiles []string, withPassphrase bool, passfile, promptLabel string) (box.SealOptions, error) {
	opts := box.SealOptions{Argon: box.DefaultArgon2id}
	for _, r := range recipients {
		pub, err := loadRecipient(r)
		if err != nil {
			return opts, err
		}
		opts.Recipients = append(opts.Recipients, pub)
	}
	for _, f := range recipientFiles {
		pubs, err := loadRecipientsFile(f)
		if err != nil {
			return opts, err
		}
		opts.Recipients = append(opts.Recipients, pubs...)
	}
	if withPassphrase || passfile != "" {
		pass, err := getPassphrase(passfile, promptLabel, true)
		if err != nil {
			return opts, err
		}
		opts.Passphrases = [][]byte{pass}
	}
	if len(opts.Recipients) == 0 && len(opts.Passphrases) == 0 {
		return opts, errors.New("sindook: provide at least one -r recipient, -R file, or -p")
	}
	return opts, nil
}

// loadCredentials resolves the identity and passphrase used for opening.
func loadCredentials(idPath string, usePass bool, passfile, passLabel string) (*xwing.PrivateKey, []byte, error) {
	usePass = usePass || passfile != ""
	if idPath == "" && !usePass {
		return nil, nil, errors.New("sindook: provide -i IDENTITY, -p, or -passfile")
	}
	var id *xwing.PrivateKey
	if idPath != "" {
		var err error
		if id, err = loadIdentity(idPath); err != nil {
			return nil, nil, err
		}
	}
	var pass []byte
	if usePass {
		var err error
		if pass, err = getPassphrase(passfile, passLabel, false); err != nil {
			return nil, nil, err
		}
	}
	return id, pass, nil
}

// getPassphrase prefers a passfile when given, falling back to the
// interactive prompt.
func getPassphrase(passfile, label string, confirm bool) ([]byte, error) {
	if passfile != "" {
		return readPassfile(passfile)
	}
	return promptPassphrase(label, confirm)
}

func promptPassphrase(label string, confirm bool) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errors.New("sindook: no terminal for the passphrase prompt, use -passfile")
		}
		tty = os.Stdin
	} else {
		defer tty.Close()
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
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
