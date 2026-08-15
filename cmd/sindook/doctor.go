package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ruddro-roy/sindook/internal/memguard"
)

const usageDoctor = `usage: sindook doctor [-json] [-check-version]

Check the local installation, configuration, and selected default identity.
This command never creates, changes, or unlocks an identity.

flags:
  -json             print one machine-readable report to stdout
  -check-version    also check GitHub for a newer release

examples:
  sindook doctor
  sindook doctor -json
  sindook doctor -check-version
`

type doctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type doctorReport struct {
	Version         string        `json:"version"`
	Platform        string        `json:"platform"`
	Executable      string        `json:"executable,omitempty"`
	ConfigDirectory string        `json:"config_directory,omitempty"`
	ConfigFile      string        `json:"config_file,omitempty"`
	Checks          []doctorCheck `json:"checks"`
	Errors          int           `json:"errors"`
	Warnings        int           `json:"warnings"`
	LatestRelease   string        `json:"latest_release,omitempty"`
	UpdateAvailable bool          `json:"update_available,omitempty"`
}

func (r *doctorReport) add(name, status, detail, remediation string) {
	r.Checks = append(r.Checks, doctorCheck{
		Name:        name,
		Status:      status,
		Detail:      detail,
		Remediation: remediation,
	})
	switch status {
	case "error":
		r.Errors++
	case "warning":
		r.Warnings++
	}
}

func cmdDoctor(args []string) error {
	fs := newFlagSet("doctor", usageDoctor)
	jsonOut := fs.Bool("json", false, "")
	checkVersion := fs.Bool("check-version", false, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 0 {
		return usagef("doctor takes no positional arguments")
	}

	report := doctorReport{
		Version:  version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Checks:   make([]doctorCheck, 0, 5),
	}
	if err := memguard.LockAll(); errors.Is(err, memguard.ErrUnsupported) {
		report.add("memory lock", "ok", "memory locking is not available on this platform; key material is not protected against swapping", "")
	} else if err != nil {
		report.add("memory lock", "warning", err.Error(), "raise the RLIMIT_MEMLOCK limit (or run with more privileges) so key material cannot be written to swap")
	} else {
		report.add("memory lock", "ok", "key material is kept in locked memory where the OS allows it", "")
	}
	if exe, err := os.Executable(); err != nil {
		report.add("executable", "warning", "could not determine the running binary: "+err.Error(), "run sindook from a normal installed path")
	} else {
		report.Executable = exe
		report.add("executable", "ok", exe, "")
	}

	checkDoctorConfig(&report)
	if *checkVersion {
		latest, err := latestSindookRelease()
		if err != nil {
			report.add("latest release", "warning", "could not check for updates: "+err.Error(), "check https://github.com/ruddro-roy/sindook/releases when online")
		} else {
			report.LatestRelease = latest
			if newer, comparable := releaseIsNewer(latest, version); comparable && newer {
				report.UpdateAvailable = true
				report.add("latest release", "warning", "a newer release is available: "+latest, "install the newer release when convenient")
			} else if comparable {
				report.add("latest release", "ok", "running version is current (latest: "+latest+")", "")
			} else {
				report.add("latest release", "warning", "latest release is "+latest+"; could not compare it with this build", "compare sindook version with the release notes")
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		fmt.Printf("Sindook %s on %s\n", report.Version, report.Platform)
		for _, check := range report.Checks {
			fmt.Printf("[%s] %s: %s\n", check.Status, check.Name, check.Detail)
			if check.Remediation != "" {
				fmt.Printf("  %s\n", check.Remediation)
			}
		}
		fmt.Printf("Summary: %d error(s), %d warning(s)\n", report.Errors, report.Warnings)
	}
	if report.Errors > 0 {
		return fmt.Errorf("sindook: doctor found %d problem(s)", report.Errors)
	}
	return nil
}

func checkDoctorConfig(report *doctorReport) {
	dir, err := sindookConfigDir()
	if err != nil {
		report.add("configuration", "error", err.Error(), "set SINDOOK_CONFIG_DIR to a writable per-user directory")
		return
	}
	report.ConfigDirectory = dir
	path := filepath.Join(dir, "config.json")
	report.ConfigFile = path

	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		report.add("configuration", "ok", "not initialized; no managed configuration exists yet", "run sindook init when you want a default identity or saved contacts")
		return
	}
	if err != nil {
		report.add("configuration", "error", "cannot inspect configuration directory: "+err.Error(), "set SINDOOK_CONFIG_DIR to a readable directory")
		return
	}
	if !info.IsDir() {
		report.add("configuration", "error", dir+" is not a directory", "set SINDOOK_CONFIG_DIR to a directory")
		return
	}

	fileInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		report.add("configuration", "ok", "configuration directory exists but has not been initialized", "run sindook init when you want a default identity or saved contacts")
		return
	}
	if err != nil {
		report.add("configuration", "error", "cannot inspect config.json: "+err.Error(), "repair the path or restore config.json from a backup")
		return
	}
	if !fileInfo.Mode().IsRegular() {
		report.add("configuration", "error", "config.json is not a regular file", "replace it with a regular Sindook config.json file")
		return
	}
	if warning := warnInsecurePerms(path, fileInfo); warning != "" {
		report.add("configuration permissions", "warning", warning, "restrict the configuration file to your account")
	}

	cfg, err := loadSindookConfig()
	if err != nil {
		report.add("configuration", "error", err.Error(), "repair config.json or move it aside and run sindook init again")
		return
	}
	report.add("configuration", "ok", fmt.Sprintf("%d saved contact(s)", len(cfg.Contacts)), "")
	if cfg.DefaultIdentity == "" {
		report.add("default identity", "ok", "not configured", "run sindook init -i IDENTITY or sindook init -o IDENTITY when wanted")
		return
	}
	identityInfo, err := os.Stat(cfg.DefaultIdentity)
	if err != nil {
		report.add("default identity", "error", "cannot access "+cfg.DefaultIdentity+": "+err.Error(), "run sindook init -i IDENTITY to select an available identity")
		return
	}
	if !identityInfo.Mode().IsRegular() {
		report.add("default identity", "error", cfg.DefaultIdentity+" is not a regular file", "select a regular identity file with sindook init -i IDENTITY")
		return
	}
	if warning := warnInsecurePerms(cfg.DefaultIdentity, identityInfo); warning != "" {
		report.add("identity permissions", "warning", warning, "restrict the identity file to your account")
	}
	if _, err := os.Stat(cfg.DefaultIdentity + ".pub"); err != nil {
		report.add("default public key", "warning", "cannot access "+cfg.DefaultIdentity+".pub: "+err.Error(), "recreate the public key with sindook pubkey -i @default > IDENTITY.pub")
	}
	report.add("default identity", "ok", cfg.DefaultIdentity, "")
}

func latestSindookRelease() (string, error) {
	repo := os.Getenv("SINDOOK_REPO")
	if repo == "" {
		repo = "ruddro-roy/sindook"
	}
	if strings.Count(repo, "/") != 1 {
		return "", errors.New("SINDOOK_REPO must be OWNER/REPOSITORY")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sindook-doctor")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub returned %s", resp.Status)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", errors.New("GitHub response did not include a release tag")
	}
	return payload.TagName, nil
}

// releaseIsNewer compares the numeric major.minor.patch part of release tags.
// It intentionally returns comparable=false for non-semantic development tags
// rather than guessing whether a local build is newer.
func releaseIsNewer(candidate, current string) (newer, comparable bool) {
	candidateParts, ok := parseReleaseParts(candidate)
	if !ok {
		return false, false
	}
	currentParts, ok := parseReleaseParts(current)
	if !ok {
		return false, false
	}
	for i := range candidateParts {
		if candidateParts[i] != currentParts[i] {
			return candidateParts[i] > currentParts[i], true
		}
	}
	return false, true
}

func parseReleaseParts(value string) ([3]int, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	value, _, _ = strings.Cut(value, "-")
	value, _, _ = strings.Cut(value, "+")
	fields := strings.Split(value, ".")
	if len(fields) != 3 {
		return [3]int{}, false
	}
	var parts [3]int
	for i, field := range fields {
		if field == "" || strings.HasPrefix(field, "+") || strings.HasPrefix(field, "-") {
			return [3]int{}, false
		}
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		parts[i] = n
	}
	return parts, true
}
