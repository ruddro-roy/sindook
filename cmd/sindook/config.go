package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const configVersion = 1

// Sindook's managed state deliberately contains public data only: saved
// recipient keys and an explicit path to an identity the user owns. Private
// identities, passphrases, and passfile paths never enter this file.
type sindookConfig struct {
	Version         int                     `json:"version"`
	DefaultIdentity string                  `json:"default_identity,omitempty"`
	Contacts        map[string]savedContact `json:"contacts,omitempty"`
}

type savedContact struct {
	PublicKey string `json:"public_key"`
	AddedAt   string `json:"added_at"`
}

func newSindookConfig() sindookConfig {
	return sindookConfig{Version: configVersion, Contacts: make(map[string]savedContact)}
}

// sindookConfigDir follows each operating system's normal per-user config
// location. SINDOOK_CONFIG_DIR is an explicit portable/test override and is
// intentionally the final Sindook directory, not a parent shared with other
// applications.
func sindookConfigDir() (string, error) {
	if override := os.Getenv("SINDOOK_CONFIG_DIR"); override != "" {
		dir, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("sindook: resolve SINDOOK_CONFIG_DIR: %w", err)
		}
		return dir, nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("sindook: cannot determine a per-user configuration directory; set SINDOOK_CONFIG_DIR: %w", err)
	}
	return filepath.Join(root, "sindook"), nil
}

func sindookConfigPath() (string, error) {
	dir, err := sindookConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func loadSindookConfig() (sindookConfig, error) {
	path, err := sindookConfigPath()
	if err != nil {
		return sindookConfig{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newSindookConfig(), nil
	}
	if err != nil {
		return sindookConfig{}, fmt.Errorf("sindook: read configuration: %w", err)
	}
	var cfg sindookConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return sindookConfig{}, fmt.Errorf("sindook: parse configuration: %w", err)
	}
	if cfg.Version != configVersion {
		return sindookConfig{}, fmt.Errorf("sindook: unsupported configuration version %d", cfg.Version)
	}
	if cfg.Contacts == nil {
		cfg.Contacts = make(map[string]savedContact)
	}
	for name, contact := range cfg.Contacts {
		normalized, err := normalizeContactName(name)
		if err != nil || normalized != name {
			return sindookConfig{}, fmt.Errorf("sindook: invalid saved contact name %q", name)
		}
		if _, err := parseSavedPublicKey(contact.PublicKey); err != nil {
			return sindookConfig{}, fmt.Errorf("sindook: saved contact @%s has an invalid public key", name)
		}
	}
	return cfg, nil
}

func saveSindookConfig(cfg sindookConfig) error {
	cfg.Version = configVersion
	if cfg.Contacts == nil {
		cfg.Contacts = make(map[string]savedContact)
	}
	dir, err := sindookConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sindook: create configuration directory: %w", err)
	}
	if err := applyPathACL(dir, true); err != nil {
		return fmt.Errorf("sindook: restrict configuration directory access: %w", err)
	}
	path := filepath.Join(dir, "config.json")
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("sindook: encode configuration: %w", err)
	}
	raw = append(raw, '\n')
	if err := writeOutputStaged(path, 0o600, func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	}); err != nil {
		return err
	}
	return applyPathACL(path, false)
}

func defaultIdentityPath() (string, error) {
	cfg, err := loadSindookConfig()
	if err != nil {
		return "", err
	}
	if cfg.DefaultIdentity == "" {
		return "", errors.New("sindook: no default identity; run sindook init -i IDENTITY or sindook init -o IDENTITY")
	}
	if _, err := os.Stat(cfg.DefaultIdentity); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("sindook: default identity %s no longer exists; run sindook init -i IDENTITY", cfg.DefaultIdentity)
		}
		return "", err
	}
	return cfg.DefaultIdentity, nil
}

func defaultPublicKeyPath() (string, error) {
	identity, err := defaultIdentityPath()
	if err != nil {
		return "", err
	}
	path := identity + ".pub"
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("sindook: default public key %s does not exist", path)
		}
		return "", err
	}
	return path, nil
}

func normalizeContactName(name string) (string, error) {
	if strings.HasPrefix(name, "@") {
		name = strings.TrimPrefix(name, "@")
	}
	if name == "" || name != strings.TrimSpace(name) || len(name) > 64 {
		return "", errors.New("contact names must be 1-64 portable characters")
	}
	name = strings.ToLower(name)
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := c >= 'a' && c <= 'z'
		digit := c >= '0' && c <= '9'
		if (i == 0 && !letter && !digit) || (i > 0 && !letter && !digit && c != '.' && c != '_' && c != '-') {
			return "", errors.New("contact names must start with a letter or number and use only letters, numbers, dot, underscore, or dash")
		}
	}
	if strings.HasSuffix(name, ".") || isWindowsReservedName(name) {
		return "", fmt.Errorf("contact name %q is not portable to Windows", name)
	}
	return name, nil
}

func isWindowsReservedName(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(strings.ToUpper(base), "COM") || strings.HasPrefix(strings.ToUpper(base), "LPT")) {
		return base[3] >= '1' && base[3] <= '9'
	}
	return false
}

func parseSavedPublicKey(value string) ([]byte, error) {
	if !strings.HasPrefix(value, pkPrefix) {
		return nil, errors.New("not a sindook public key")
	}
	return decodeRecipient(strings.TrimPrefix(value, pkPrefix))
}

func canonicalPublicKey(pub []byte) string {
	return pkPrefix + base64.RawStdEncoding.EncodeToString(pub)
}

// contactFingerprint returns the short key fingerprint shown by
// "contacts list": the first 16 bytes of SHA-256 over the decoded public
// key, hex-encoded. "contacts show" and -json output carry the full key.
func contactFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:16])
}

func loadContact(name string) ([]byte, error) {
	normalized, err := normalizeContactName(name)
	if err != nil {
		return nil, fmt.Errorf("sindook: invalid contact alias @%s: %w", name, err)
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return nil, err
	}
	contact, ok := cfg.Contacts[normalized]
	if !ok {
		return nil, fmt.Errorf("sindook: unknown contact @%s; add it with sindook contacts add %s PUBLIC_KEY_OR_FILE", normalized, normalized)
	}
	pub, err := parseSavedPublicKey(contact.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sindook: saved contact @%s has an invalid public key", normalized)
	}
	return pub, nil
}

const usageInit = `usage: sindook init [-i IDENTITY | -o FILE] [-p] [-passfile FILE]
                    [-identity-passfile FILE] [-f]

Create your first identity at an explicit path, or select an existing one as
the default for -i @default and -r @default. Sindook stores only that path
and public contact aliases in its per-user configuration; it never copies a
private identity or passphrase into the configuration directory.

flags:
  -i IDENTITY         select an existing identity as the default
  -o FILE             create a new identity here (default sindook.key)
  -p                  protect a new identity with a passphrase
  -passfile FILE      read a new identity's protection passphrase from FILE
  -identity-passfile FILE
                      read an existing protected identity's passphrase
  -f                  overwrite a newly-created identity

examples:
  sindook init -o ~/Documents/sindook-personal.key -p
  sindook init -i ~/Documents/sindook-personal.key
  sindook seal -r @default report.pdf
  sindook open -i @default report.pdf.sindook
`

func cmdInit(args []string) error {
	fs := newFlagSet("init", usageInit)
	existing := fs.String("i", "", "")
	out := fs.String("o", "sindook.key", "")
	protect := fs.Bool("p", false, "")
	passfile := fs.String("passfile", "", "")
	identityPassfile := fs.String("identity-passfile", "", "")
	force := fs.Bool("f", false, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 0 {
		return usagef("init takes no positional arguments")
	}
	var outSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "o" {
			outSet = true
		}
	})

	if *existing != "" {
		if *protect || *passfile != "" {
			return usagef("-p and -passfile create a new identity; omit -i or use -identity-passfile")
		}
		if outSet || *force {
			return usagef("-i selects an existing identity and cannot be combined with -o or -f")
		}
		identityPath, err := resolveIdentityPath(*existing)
		if err != nil {
			return err
		}
		id, err := loadIdentityWithPassfile(identityPath, *identityPassfile)
		if err != nil {
			return err
		}
		defer id.Wipe()
		path, err := filepath.Abs(identityPath)
		if err != nil {
			return err
		}
		if err := setDefaultIdentity(path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "default identity: %s\n", path)
		fmt.Println(canonicalPublicKey(id.PublicKey()))
		return nil
	}
	if *identityPassfile != "" {
		return usagef("-identity-passfile requires -i IDENTITY")
	}

	*protect = *protect || *passfile != ""
	pub, err := createIdentity(*out, *protect, *passfile, *force)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := setDefaultIdentity(path); err != nil {
		return fmt.Errorf("sindook: created identity %s but could not set it as default: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "identity: %s\npublic key: %s\ndefault identity: %s\n", *out, *out+".pub", path)
	fmt.Println(pub)
	return nil
}

func setDefaultIdentity(path string) error {
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	cfg.DefaultIdentity = path
	return saveSindookConfig(cfg)
}

const usageContacts = `usage: sindook contacts [list [-json] | add [-f] NAME PUBLIC_KEY_OR_FILE |
                         show NAME | remove NAME]

Save shareable recipient public keys under portable, case-insensitive names.
Use a saved contact anywhere a recipient is accepted: -r @alice. The config
file contains public keys and an optional default identity path only; it never
contains private keys or passphrases. list prints short sha256 fingerprints;
use show NAME or -json for full public keys.

examples:
  sindook contacts add alice alice.key.pub
  sindook contacts add finance-team team.keys
  sindook contacts list
  sindook seal -r @alice report.pdf
  sindook contacts remove alice
`

type contactReport struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	AddedAt   string `json:"added_at"`
}

func cmdContacts(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return cmdContactsList(args)
	}
	switch args[0] {
	case "list":
		return cmdContactsList(args[1:])
	case "add":
		return cmdContactsAdd(args[1:])
	case "show":
		return cmdContactsShow(args[1:])
	case "remove", "rm":
		return cmdContactsRemove(args[1:])
	default:
		return usagef("unknown contacts command %q\n\n%s", args[0], usageContacts)
	}
}

func sortedContactReports(cfg sindookConfig) []contactReport {
	names := make([]string, 0, len(cfg.Contacts))
	for name := range cfg.Contacts {
		names = append(names, name)
	}
	sort.Strings(names)
	reports := make([]contactReport, 0, len(names))
	for _, name := range names {
		contact := cfg.Contacts[name]
		reports = append(reports, contactReport{Name: name, PublicKey: contact.PublicKey, AddedAt: contact.AddedAt})
	}
	return reports
}

func cmdContactsList(args []string) error {
	fs := newFlagSet("contacts list", usageContacts)
	jsonOut := fs.Bool("json", false, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 0 {
		return usagef("contacts list takes no positional arguments")
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	reports := sortedContactReports(cfg)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(reports)
	}
	if len(reports) == 0 {
		fmt.Println("no saved contacts; add one with: sindook contacts add NAME PUBLIC_KEY_OR_FILE")
		return nil
	}
	for _, report := range reports {
		pub, err := parseSavedPublicKey(report.PublicKey)
		if err != nil {
			fmt.Printf("@%s  (invalid key)\n", report.Name)
			continue
		}
		fmt.Printf("@%s  %s\n", report.Name, contactFingerprint(pub))
	}
	return nil
}

func cmdContactsAdd(args []string) error {
	fs := newFlagSet("contacts add", usageContacts)
	force := fs.Bool("f", false, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 2 {
		return usagef("contacts add needs NAME and PUBLIC_KEY_OR_FILE")
	}
	name, err := normalizeContactName(fs.Arg(0))
	if err != nil {
		return usagef("invalid contact name: %v", err)
	}
	pub, err := loadRecipient(fs.Arg(1))
	if err != nil {
		return err
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	if _, exists := cfg.Contacts[name]; exists && !*force {
		return fmt.Errorf("sindook: contact @%s already exists; use -f to replace it", name)
	}
	cfg.Contacts[name] = savedContact{PublicKey: canonicalPublicKey(pub), AddedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := saveSindookConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("saved contact @%s\n", name)
	return nil
}

func cmdContactsShow(args []string) error {
	if len(args) != 1 {
		return usagef("contacts show needs one NAME")
	}
	name, err := normalizeContactName(args[0])
	if err != nil {
		return usagef("invalid contact name: %v", err)
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	contact, ok := cfg.Contacts[name]
	if !ok {
		return fmt.Errorf("sindook: unknown contact @%s", name)
	}
	fmt.Println(contact.PublicKey)
	return nil
}

func cmdContactsRemove(args []string) error {
	if len(args) != 1 {
		return usagef("contacts remove needs one NAME")
	}
	name, err := normalizeContactName(args[0])
	if err != nil {
		return usagef("invalid contact name: %v", err)
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	if _, ok := cfg.Contacts[name]; !ok {
		return fmt.Errorf("sindook: unknown contact @%s", name)
	}
	delete(cfg.Contacts, name)
	if err := saveSindookConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("removed contact @%s\n", name)
	return nil
}

const usagePaths = `usage: sindook paths [-json]

Show the operating-system-specific directory used for Sindook's public
contacts and default identity path. SINDOOK_CONFIG_DIR overrides the location
for a portable install or an isolated automation run.
`

type pathsReport struct {
	ConfigDirectory      string `json:"config_directory"`
	ConfigFile           string `json:"config_file"`
	DefaultIdentity      string `json:"default_identity,omitempty"`
	DefaultIdentityReady bool   `json:"default_identity_ready"`
	Contacts             int    `json:"contacts"`
}

func cmdPaths(args []string) error {
	fs := newFlagSet("paths", usagePaths)
	jsonOut := fs.Bool("json", false, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 0 {
		return usagef("paths takes no positional arguments")
	}
	dir, err := sindookConfigDir()
	if err != nil {
		return err
	}
	cfg, err := loadSindookConfig()
	if err != nil {
		return err
	}
	report := pathsReport{
		ConfigDirectory: dir,
		ConfigFile:      filepath.Join(dir, "config.json"),
		DefaultIdentity: cfg.DefaultIdentity,
		Contacts:        len(cfg.Contacts),
	}
	if cfg.DefaultIdentity != "" {
		if info, err := os.Stat(cfg.DefaultIdentity); err == nil && info.Mode().IsRegular() {
			report.DefaultIdentityReady = true
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Printf("configuration: %s\n", report.ConfigDirectory)
	fmt.Printf("config file: %s\n", report.ConfigFile)
	if report.DefaultIdentity == "" {
		fmt.Println("default identity: not configured")
	} else if report.DefaultIdentityReady {
		fmt.Printf("default identity: %s\n", report.DefaultIdentity)
	} else {
		fmt.Printf("default identity: %s (missing)\n", report.DefaultIdentity)
	}
	fmt.Printf("saved contacts: %d\n", report.Contacts)
	return nil
}
