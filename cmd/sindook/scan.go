package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const usageScan = `usage: sindook scan tls [-json] [-timeout SECONDS] HOST[:PORT]...
       sindook scan files [-json] [PATH...]

Audit cryptographic posture without changing anything. Both modes are
strictly read-only: scan opens ordinary connections or reads files and
never sends exploit payloads, guesses credentials, or captures traffic.

tls audits live endpoints (port 443 unless given): certificate expiry
and key strength, chain and hostname validity, legacy protocol support,
and whether the server offers the hybrid post-quantum key exchange
X25519MLKEM768. Endpoints without it are exposed to harvest-now,
decrypt-later collection.

files audits local paths (default: the current directory) for private
keys and certificates: unencrypted or world-readable private keys,
expired or soon-expiring certificates, and weak key sizes.

flags:
  -json     print one machine-readable report to stdout
  -timeout SECONDS
            per-connection timeout for tls scans (default 10)

examples:
  sindook scan tls example.com mail.example.com:993
  sindook scan files ~/.ssh /etc/ssl/private
  sindook scan tls -json example.com | jq '.errors'
`

// scanReport mirrors the doctor report shape so fleet tooling can parse
// both with one decoder: checks carry name/status/detail/remediation and
// the report totals errors and warnings.
type scanReport struct {
	Version  string       `json:"version"`
	Platform string       `json:"platform"`
	Mode     string       `json:"mode"`
	Targets  []scanTarget `json:"targets"`
	Errors   int          `json:"errors"`
	Warnings int          `json:"warnings"`
}

type scanTarget struct {
	Target   string        `json:"target"`
	Checks   []doctorCheck `json:"checks"`
	Errors   int           `json:"errors"`
	Warnings int           `json:"warnings"`
}

func (t *scanTarget) add(name, status, detail, remediation string) {
	t.Checks = append(t.Checks, doctorCheck{
		Name:        name,
		Status:      status,
		Detail:      detail,
		Remediation: remediation,
	})
	switch status {
	case "error":
		t.Errors++
	case "warning":
		t.Warnings++
	}
}

func cmdScan(args []string) error {
	if len(args) == 0 {
		return usagef("scan needs a mode: tls or files, see 'sindook help scan'")
	}
	mode, rest := args[0], args[1:]
	switch mode {
	case "tls":
		return cmdScanTLS(rest)
	case "files":
		return cmdScanFiles(rest)
	default:
		return usagef("unknown scan mode %q: use tls or files", mode)
	}
}

func newScanReport(mode string) scanReport {
	return scanReport{
		Version:  baseVersion(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Mode:     mode,
	}
}

// emitScanReport prints the report in the selected format and converts
// error findings into a non-zero exit, matching doctor's contract.
func emitScanReport(report scanReport, jsonOut bool) error {
	for _, t := range report.Targets {
		report.Errors += t.Errors
		report.Warnings += t.Warnings
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		fmt.Printf("Sindook %s scan %s on %s\n", report.Version, report.Mode, report.Platform)
		for _, t := range report.Targets {
			fmt.Printf("\n%s\n", t.Target)
			for _, check := range t.Checks {
				fmt.Printf("[%s] %s: %s\n", doctorStatusLabel(check.Status), check.Name, check.Detail)
				if check.Remediation != "" {
					fmt.Printf("  -> %s\n", check.Remediation)
				}
			}
		}
		summary := fmt.Sprintf("\nSummary: %d target(s), %d error(s), %d warning(s)",
			len(report.Targets), report.Errors, report.Warnings)
		if isDoctorTerminal() && report.Errors > 0 {
			summary = "\x1b[31m" + summary + "\x1b[0m"
		} else if isDoctorTerminal() && report.Warnings > 0 {
			summary = "\x1b[33m" + summary + "\x1b[0m"
		} else if isDoctorTerminal() {
			summary = "\x1b[32m" + summary + "\x1b[0m"
		}
		fmt.Println(summary)
	}
	if report.Errors > 0 {
		return fmt.Errorf("sindook: scan found %d problem(s)", report.Errors)
	}
	return nil
}

// ---------------------------------------------------------------------------
// scan tls

const scanMaxParallel = 8

func cmdScanTLS(args []string) error {
	fs := newFlagSet("scan tls", usageScan)
	jsonOut := fs.Bool("json", false, "")
	timeoutSec := fs.Int("timeout", 10, "")
	parseInterspersedFlags(fs, args)
	if fs.NArg() == 0 {
		return usagef("scan tls needs at least one HOST[:PORT]")
	}
	if *timeoutSec <= 0 {
		return usagef("scan tls -timeout must be positive")
	}
	timeout := time.Duration(*timeoutSec) * time.Second

	targets := make([]scanTarget, fs.NArg())
	var wg sync.WaitGroup
	sem := make(chan struct{}, scanMaxParallel)
	for i, arg := range fs.Args() {
		wg.Add(1)
		go func(i int, arg string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			targets[i] = scanTLSTarget(arg, timeout)
		}(i, arg)
	}
	wg.Wait()

	report := newScanReport("tls")
	report.Targets = targets
	return emitScanReport(report, *jsonOut)
}

// splitScanTarget normalizes HOST[:PORT] to a dial address and SNI name,
// defaulting to port 443 and accepting bracketed IPv6 literals.
func splitScanTarget(arg string) (addr, sni string, err error) {
	host, port, splitErr := net.SplitHostPort(arg)
	if splitErr != nil {
		host, port = strings.Trim(arg, "[]"), "443"
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid target %q", arg)
	}
	return net.JoinHostPort(host, port), host, nil
}

func scanTLSTarget(arg string, timeout time.Duration) scanTarget {
	t := scanTarget{Target: arg}
	addr, sni, err := splitScanTarget(arg)
	if err != nil {
		t.add("target", "error", err.Error(), "use HOST or HOST:PORT")
		return t
	}

	state, chainErr, dialErr := scanHandshake(addr, sni, timeout, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	})
	if dialErr != nil {
		t.add("connection", "error", dialErr.Error(), "check that the host is reachable and speaks TLS on this port")
		return t
	}
	t.add("connection", "ok", "TLS handshake completed", "")

	if chainErr != nil {
		t.add("certificate chain", "error", chainErr.Error(), "serve a complete chain from a trusted CA, or distribute the private CA to clients")
	} else {
		t.add("certificate chain", "ok", "chain verifies against system roots", "")
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if err := leaf.VerifyHostname(sni); err != nil {
			t.add("hostname", "error", err.Error(), "reissue the certificate with a SubjectAltName covering this host")
		} else {
			t.add("hostname", "ok", "certificate covers "+sni, "")
		}
		name, status, detail, remediation := certExpiryCheck(leaf, time.Now())
		t.add(name, status, detail, remediation)
		name, status, detail, remediation = certKeyCheck(leaf)
		t.add(name, status, detail, remediation)
	}

	t.add(tlsVersionCheck(state.Version))

	if legacy, ok := scanProbeLegacy(addr, sni, timeout); ok && legacy {
		t.add("legacy protocols", "warning", "server accepts TLS 1.1 or older", "disable TLS 1.0 and 1.1; they are deprecated by RFC 8996")
	} else if ok {
		t.add("legacy protocols", "ok", "TLS 1.1 and older are rejected", "")
	}

	pqStatus, pqDetail, pqRemediation := scanProbePQ(addr, sni, timeout, state)
	t.add("post-quantum key exchange", pqStatus, pqDetail, pqRemediation)
	return t
}

// scanHandshake performs one TLS handshake. A certificate that fails
// verification is downgraded to a chain error rather than a dial error, so
// the scan can still report on protocol, expiry, and key strength.
func scanHandshake(addr, sni string, timeout time.Duration, cfg *tls.Config) (tls.ConnectionState, error, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		state := conn.(*tls.Conn).ConnectionState()
		conn.Close()
		return state, nil, nil
	}
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		return tls.ConnectionState{}, nil, err
	}
	insecure := cfg.Clone()
	insecure.InsecureSkipVerify = true
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
	defer cancel2()
	dialer = &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: insecure}
	conn, err2 := dialer.DialContext(ctx2, "tcp", addr)
	if err2 != nil {
		return tls.ConnectionState{}, nil, err
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	return state, certErr, nil
}

// scanProbeLegacy reports whether the server completes a TLS 1.0/1.1
// handshake. ok is false when the probe could not run, for example when the
// local Go runtime refuses to offer legacy versions at all.
func scanProbeLegacy(addr, sni string, timeout time.Duration) (legacy, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
		InsecureSkipVerify: true,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return true, true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false, false
	}
	return false, true
}

// scanProbePQ decides post-quantum readiness. The baseline handshake already
// reveals the negotiated group; when the server chose a classical group for
// our default offer, a second handshake restricted to X25519MLKEM768 asks
// whether the server could have done better.
func scanProbePQ(addr, sni string, timeout time.Duration, baseline tls.ConnectionState) (status, detail, remediation string) {
	const fix = "enable the hybrid key exchange X25519MLKEM768 on the server; without it recorded TLS traffic can be decrypted once large quantum computers exist"
	if baseline.CurveID == tls.X25519MLKEM768 {
		return "ok", "negotiated X25519MLKEM768", ""
	}
	if baseline.Version < tls.VersionTLS13 {
		return "warning", "hybrid key exchange needs TLS 1.3; server negotiated an older version", fix
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		InsecureSkipVerify: true,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "warning", "server does not support X25519MLKEM768", fix
	}
	conn.Close()
	return "ok", "X25519MLKEM768 supported (not preferred for this client's default offer)", ""
}

func tlsVersionCheck(version uint16) (name, status, detail, remediation string) {
	name = "protocol"
	switch version {
	case tls.VersionTLS13:
		return name, "ok", "negotiated TLS 1.3", ""
	case tls.VersionTLS12:
		return name, "ok", "negotiated TLS 1.2", "prefer TLS 1.3 where clients allow it"
	default:
		return name, "error", fmt.Sprintf("negotiated obsolete protocol version %#x", version), "require at least TLS 1.2"
	}
}

const scanExpiryWarning = 30 * 24 * time.Hour

func certExpiryCheck(cert *x509.Certificate, now time.Time) (name, status, detail, remediation string) {
	name = "certificate expiry"
	switch {
	case now.After(cert.NotAfter):
		return name, "error",
			fmt.Sprintf("certificate expired %s", cert.NotAfter.Format(time.DateOnly)),
			"renew the certificate"
	case now.Before(cert.NotBefore):
		return name, "error",
			fmt.Sprintf("certificate not valid before %s", cert.NotBefore.Format(time.DateOnly)),
			"check the issuing pipeline and host clock"
	case cert.NotAfter.Sub(now) < scanExpiryWarning:
		return name, "warning",
			fmt.Sprintf("certificate expires %s (%d day(s) left)",
				cert.NotAfter.Format(time.DateOnly), int(cert.NotAfter.Sub(now).Hours()/24)),
			"renew the certificate before it lapses"
	default:
		return name, "ok",
			fmt.Sprintf("valid until %s", cert.NotAfter.Format(time.DateOnly)), ""
	}
}

// certKeyCheck grades the public key of a certificate. Every classical
// algorithm carries the quantum note: the point of the scan is a crypto
// inventory, and signatures are the part that cannot be fixed by TLS
// configuration alone.
func certKeyCheck(cert *x509.Certificate) (name, status, detail, remediation string) {
	name = "certificate key"
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		switch {
		case bits < 2048:
			return name, "error", fmt.Sprintf("RSA-%d is breakable with classical hardware", bits),
				"reissue with at least RSA-3072 or an elliptic-curve key"
		case bits < 3072:
			return name, "warning", fmt.Sprintf("RSA-%d (below the 3072-bit recommendation for use beyond 2030; quantum-vulnerable)", bits),
				"reissue with at least RSA-3072 and plan a post-quantum migration"
		default:
			return name, "ok", fmt.Sprintf("RSA-%d (classical strength adequate; quantum-vulnerable like all RSA)", bits), ""
		}
	case *ecdsa.PublicKey:
		return name, "ok", fmt.Sprintf("ECDSA %s (quantum-vulnerable like all elliptic-curve keys)", key.Curve.Params().Name), ""
	case ed25519.PublicKey:
		return name, "ok", "Ed25519 (quantum-vulnerable like all elliptic-curve keys)", ""
	default:
		return name, "ok", fmt.Sprintf("%T", cert.PublicKey), ""
	}
}

// ---------------------------------------------------------------------------
// scan files

// scanFileMax bounds how much of a candidate file is read; genuine key and
// certificate files are far smaller.
const scanFileMax = 1 << 20

func cmdScanFiles(args []string) error {
	fset := newFlagSet("scan files", usageScan)
	jsonOut := fset.Bool("json", false, "")
	parseInterspersedFlags(fset, args)
	roots := fset.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	report := newScanReport("files")
	seen := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				t := scanTarget{Target: path}
				t.add("access", "warning", err.Error(), "check permissions on the path")
				report.Targets = append(report.Targets, t)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !isScanCandidate(d.Name()) {
				return nil
			}
			seen++
			if t, relevant := scanOneFile(path); relevant {
				report.Targets = append(report.Targets, t)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if seen == 0 {
		fmt.Fprintln(os.Stderr, "sindook: scan files found no key or certificate files")
	}
	return emitScanReport(report, *jsonOut)
}

// isScanCandidate matches file names that plausibly hold key material or
// certificates, keeping the walk cheap on large trees.
func isScanCandidate(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".key", ".crt", ".cer", ".ppk", ".p12", ".pfx":
		return true
	}
	base := strings.ToLower(name)
	return base == "id_rsa" || base == "id_ecdsa" || base == "id_ed25519" || base == "id_dsa"
}

// scanOneFile classifies one candidate. relevant is false when the file
// turned out to hold nothing recognizable (for example a .key file of
// unrelated data), keeping reports focused.
func scanOneFile(path string) (t scanTarget, relevant bool) {
	t = scanTarget{Target: path}
	f, err := os.Open(path)
	if err != nil {
		t.add("access", "warning", err.Error(), "check permissions on the file")
		return t, true
	}
	defer f.Close()
	data := make([]byte, scanFileMax+1)
	n, _ := f.Read(data)
	data = data[:n]
	if n > scanFileMax {
		return t, false
	}

	info, statErr := os.Stat(path)
	private := false
	found := false

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		found = true
		switch {
		case block.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.add("certificate", "warning", "unparseable certificate block: "+err.Error(), "verify the file is intact")
				continue
			}
			t.add(certExpiryCheck(cert, time.Now()))
			t.add(certKeyCheck(cert))
		case block.Type == "ENCRYPTED PRIVATE KEY":
			private = true
			t.add("private key", "ok", "PKCS#8 key is passphrase-protected", "")
		case block.Type == "OPENSSH PRIVATE KEY":
			private = true
			t.add(scanOpenSSHKey(data))
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			private = true
			if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
				t.add("private key", "ok", "legacy PEM key is passphrase-protected", "")
			} else {
				t.add("private key", "warning", "unencrypted "+block.Type+" on disk",
					"protect it with a passphrase, or seal it: sindook seal "+path)
			}
		}
	}

	if !found {
		switch {
		case strings.HasPrefix(string(data), "PuTTY-User-Key-File-"):
			found, private = true, true
			t.add(scanPuTTYKey(data, path))
		case looksLikeDERCertificate(data):
			cert, err := x509.ParseCertificate(data)
			if err == nil {
				found = true
				t.add(certExpiryCheck(cert, time.Now()))
				t.add(certKeyCheck(cert))
			}
		case strings.ToLower(filepath.Ext(path)) == ".p12" || strings.ToLower(filepath.Ext(path)) == ".pfx":
			found, private = true, true
			t.add("private key", "ok", "PKCS#12 container (always encrypted; strength depends on its passphrase)", "")
		}
	}
	if !found {
		return t, false
	}

	if private && statErr == nil {
		if warning := warnInsecurePerms(path, info); warning != "" {
			t.add("permissions", "warning", warning, "restrict the key file to your account")
		}
	}
	return t, true
}

func scanOpenSSHKey(data []byte) (name, status, detail, remediation string) {
	name = "private key"
	_, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return name, "ok", "OpenSSH key is passphrase-protected", ""
	case err != nil:
		return name, "warning", "unparseable OpenSSH key: " + err.Error(), "verify the file is intact"
	default:
		return name, "warning", "unencrypted OpenSSH private key on disk",
			"add a passphrase: ssh-keygen -p -f the key file"
	}
}

func scanPuTTYKey(data []byte, path string) (name, status, detail, remediation string) {
	name = "private key"
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "Encryption:"); ok {
			if strings.TrimSpace(value) == "none" {
				return name, "warning", "unencrypted PuTTY private key on disk",
					"set a passphrase in PuTTYgen, or seal it: sindook seal " + path
			}
			return name, "ok", "PuTTY key is passphrase-protected", ""
		}
	}
	return name, "warning", "PuTTY key without a readable Encryption header", "verify the file is intact"
}

// looksLikeDERCertificate cheaply gates the DER parse attempt on the ASN.1
// SEQUENCE tag so arbitrary binary files are not parsed as certificates.
func looksLikeDERCertificate(data []byte) bool {
	return len(data) > 4 && data[0] == 0x30 && (data[1]&0x80) != 0
}
