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
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ruddro-roy/sindook/internal/memguard"
)

const usageScan = `usage: sindook scan tls [-json] [-timeout SECONDS] HOST[:PORT]...
       sindook scan files [-json] [PATH...]

Audit cryptographic posture without changing anything. Scan endpoints you
operate or are authorized to assess. Both modes are strictly read-only:
scan opens ordinary connections or reads files and never sends exploit
payloads, guesses credentials, or captures traffic.

tls audits live endpoints (port 443 unless given): certificate expiry
and key strength, chain and hostname validity, legacy protocol
support, and whether the server supports a hybrid post-quantum key
exchange (X25519MLKEM768 or the SECP+ML-KEM groups). Recorded traffic
from endpoints without one may be decryptable by a future quantum
computer (harvest now, decrypt later). Ports that upgrade with
STARTTLS (such as 25 and 587) are not supported; scan implicit-TLS
ports. A probe that cannot reach a conclusion says so instead of
guessing.

files audits local paths (default: the current directory) for private
keys and certificates found by common file names: unencrypted private
keys, key files with permissive file modes (best effort, platform
dependent), expired or soon-expiring certificates, and weak key sizes.

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

// scanSafe strips terminal control characters from untrusted text (file
// names, TLS error strings) so findings cannot be spoofed or erased by
// ANSI escape sequences when printed.
func scanSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return '?'
		}
		return r
	}, s)
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
			fmt.Printf("\n%s\n", scanSafe(t.Target))
			for _, check := range t.Checks {
				fmt.Printf("[%s] %s: %s\n", doctorStatusLabel(check.Status), check.Name, scanSafe(check.Detail))
				if check.Remediation != "" {
					fmt.Printf("  -> %s\n", scanSafe(check.Remediation))
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

	operands := fs.Args()
	targets := make([]scanTarget, len(operands))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(scanMaxParallel, len(operands)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				targets[i] = scanTLSTarget(operands[i], timeout)
			}
		}()
	}
	for i := range operands {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	report := newScanReport("tls")
	report.Targets = targets
	return emitScanReport(report, *jsonOut)
}

// splitScanTarget normalizes HOST[:PORT] to a dial address and SNI name.
// The port defaults to 443 and must be numeric when given. IPv6 literals
// with an explicit port need brackets; bare IPv6 literals are accepted.
func splitScanTarget(arg string) (addr, sni string, err error) {
	host, port, splitErr := net.SplitHostPort(arg)
	if splitErr != nil {
		bare := strings.Trim(arg, "[]")
		if bare == "" {
			return "", "", fmt.Errorf("invalid target %q", arg)
		}
		if strings.Contains(bare, ":") && net.ParseIP(bare) == nil {
			return "", "", fmt.Errorf("invalid target %q (an IPv6 literal with a port needs brackets: [addr]:port)", arg)
		}
		host, port = bare, "443"
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid target %q", arg)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("invalid port %q in target %q", port, arg)
	}
	return net.JoinHostPort(host, port), host, nil
}

// probeOutcome classifies a failed TLS handshake by evidence strength: a
// TLS alert from the peer proves the server made a decision; anything else
// proves nothing about the server.
type probeOutcome int

const (
	probeRefused      probeOutcome = iota // the server answered at the TLS layer and declined
	probeInconclusive                     // timeout, reset, or transport failure: no server verdict
	probeUnavailable                      // this client could not even make the offer
)

func classifyProbeErr(err error) probeOutcome {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no supported versions") ||
		strings.Contains(msg, "no supported elliptic curves") ||
		strings.Contains(msg, "no cipher suites"):
		return probeUnavailable
	case strings.Contains(msg, "remote error"):
		return probeRefused
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return probeInconclusive
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probeInconclusive
	}
	return probeInconclusive
}

// scanDial performs one TLS handshake with certificate verification
// disabled and returns the connection state. Chain, hostname, and expiry
// are judged separately so one failed property cannot mask the others.
func scanDial(addr string, timeout time.Duration, cfg *tls.Config) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cfg.InsecureSkipVerify = true
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	return state, nil
}

// legacyCipherSuites re-enables the CBC and RSA-key-exchange suites that
// real TLS 1.0/1.1 deployments use but modern Go clients no longer offer
// by default. Without them a legacy-capable server can fail the probe and
// be reported as clean.
var legacyCipherSuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
}

func legacyConfig(sni string) *tls.Config {
	return &tls.Config{
		ServerName:   sni,
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
		CipherSuites: legacyCipherSuites,
	}
}

// hybridGroups are the post-quantum hybrid key exchanges this client can
// offer and recognize. Any of them counts as post-quantum ready.
var hybridGroups = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
}

func isHybridGroup(id tls.CurveID) bool {
	for _, g := range hybridGroups {
		if id == g {
			return true
		}
	}
	return false
}

func scanTLSTarget(arg string, timeout time.Duration) scanTarget {
	t := scanTarget{Target: arg}
	addr, sni, err := splitScanTarget(arg)
	if err != nil {
		t.add("target", "error", err.Error(), "use HOST or HOST:PORT")
		return t
	}

	state, dialErr := scanDial(addr, timeout, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	if dialErr != nil {
		// A server that cannot do TLS 1.2 may still be a live legacy-only
		// endpoint, which is a finding, not an unreachable host.
		if legacyState, legacyErr := scanDial(addr, timeout, legacyConfig(sni)); legacyErr == nil {
			t.add("connection", "ok", "TLS handshake completed", "")
			t.add("protocol", "error",
				fmt.Sprintf("server only completed %s; the TLS 1.2 handshake failed (%v)", tlsVersionName(legacyState.Version), dialErr),
				"enable TLS 1.2 or 1.3; TLS 1.0 and 1.1 are deprecated by RFC 8996")
			addCertChecks(&t, legacyState, sni)
			return t
		}
		t.add("connection", "error", dialErr.Error(), "check that the host is reachable and speaks TLS on this port")
		return t
	}
	t.add("connection", "ok", "TLS handshake completed", "")
	addChainCheck(&t, state)
	addCertChecks(&t, state, sni)
	t.add(tlsVersionCheck(state.Version))
	addLegacyCheck(&t, addr, sni, timeout)
	addPQCheck(&t, addr, sni, timeout, state)
	return t
}

// addChainCheck verifies the chain against system roots independently of
// hostname and expiry, which have their own checks. A chain whose only
// defect is an expired certificate is reported under expiry, not as a
// missing or untrusted chain.
func addChainCheck(t *scanTarget, state tls.ConnectionState) {
	if len(state.PeerCertificates) == 0 {
		t.add("certificate chain", "error", "server presented no certificates", "configure a server certificate")
		return
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates})
	if err == nil {
		t.add("certificate chain", "ok", "chain verifies against system roots", "")
		return
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		t.add("certificate chain", "warning", "chain contains an expired certificate; see the expiry check", "renew the expired certificate")
		return
	}
	t.add("certificate chain", "error", err.Error(), "serve a complete chain from a trusted CA, or distribute the private CA to clients")
}

func addCertChecks(t *scanTarget, state tls.ConnectionState, sni string) {
	if len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	if err := leaf.VerifyHostname(sni); err != nil {
		t.add("hostname", "error", err.Error(), "reissue the certificate with a SubjectAltName covering this host")
	} else {
		t.add("hostname", "ok", "certificate covers "+sni, "")
	}
	t.add(certExpiryCheck(leaf, time.Now()))
	t.add(certKeyCheck(leaf))
}

// addLegacyCheck reports whether the server accepts TLS 1.0/1.1. Only a
// completed handshake or a TLS alert from the server is treated as
// evidence; every other failure is reported as inconclusive.
func addLegacyCheck(t *scanTarget, addr, sni string, timeout time.Duration) {
	const name = "legacy protocols"
	_, err := scanDial(addr, timeout, legacyConfig(sni))
	if err == nil {
		t.add(name, "warning", "server accepts TLS 1.1 or older", "disable TLS 1.0 and 1.1; they are deprecated by RFC 8996")
		return
	}
	switch classifyProbeErr(err) {
	case probeRefused:
		t.add(name, "ok", "server refused a TLS 1.0/1.1 handshake", "")
	case probeUnavailable:
		t.add(name, "warning", "probe could not run on this system: "+err.Error(), "verify legacy protocol support with another tool, such as testssl.sh")
	default:
		t.add(name, "warning", "probe inconclusive: "+err.Error(), "retry, or verify legacy protocol support with another tool")
	}
}

// addPQCheck decides post-quantum readiness. The baseline handshake
// already reveals the negotiated group. When the server chose a classical
// group for the default offer, a second handshake restricted to hybrid
// groups asks whether the server could have done better, and the answer
// only counts when the negotiated group proves it.
func addPQCheck(t *scanTarget, addr, sni string, timeout time.Duration, baseline tls.ConnectionState) {
	const name = "post-quantum key exchange"
	const fix = "enable a hybrid key exchange (X25519MLKEM768); recorded traffic without one may be decryptable by a future quantum computer"
	if isHybridGroup(baseline.CurveID) {
		t.add(name, "ok", "negotiated "+baseline.CurveID.String(), "")
		return
	}
	if baseline.Version < tls.VersionTLS13 {
		t.add(name, "warning", "hybrid key exchange needs TLS 1.3; the server negotiated an older version", fix)
		return
	}
	state, err := scanDial(addr, timeout, &tls.Config{
		ServerName:       sni,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), hybridGroups...),
	})
	if err == nil {
		if isHybridGroup(state.CurveID) {
			t.add(name, "ok", state.CurveID.String()+" supported (not chosen for this client's default offer)", "")
		} else {
			t.add(name, "warning", "hybrid-only offer negotiated non-hybrid group "+state.CurveID.String()+"; a middlebox may be interfering", fix)
		}
		return
	}
	switch classifyProbeErr(err) {
	case probeRefused:
		t.add(name, "warning", "server refused a hybrid-only key exchange offer", fix)
	case probeUnavailable:
		t.add(name, "warning", "probe could not run on this system: "+err.Error(), "verify hybrid key exchange support with another tool")
	default:
		t.add(name, "warning", "probe inconclusive: "+err.Error(), "retry, or verify hybrid key exchange support with another tool")
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("protocol %#x", version)
	}
}

func tlsVersionCheck(version uint16) (name, status, detail, remediation string) {
	name = "protocol"
	switch version {
	case tls.VersionTLS13:
		return name, "ok", "negotiated TLS 1.3", ""
	case tls.VersionTLS12:
		return name, "ok", "negotiated TLS 1.2", "prefer TLS 1.3 where clients allow it"
	default:
		return name, "error", "negotiated obsolete " + tlsVersionName(version), "require at least TLS 1.2"
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
	case cert.NotAfter.Sub(now) <= scanExpiryWarning:
		return name, "warning",
			fmt.Sprintf("certificate expires %s (%d day(s) left)",
				cert.NotAfter.Format(time.DateOnly), int(cert.NotAfter.Sub(now).Hours()/24)),
			"renew the certificate before it lapses"
	default:
		return name, "ok",
			fmt.Sprintf("valid until %s", cert.NotAfter.Format(time.DateOnly)), ""
	}
}

// certKeyCheck grades the public key of a certificate. Classical
// algorithms carry the quantum note because the scan is a crypto
// inventory; the grading itself follows current classical guidance.
func certKeyCheck(cert *x509.Certificate) (name, status, detail, remediation string) {
	name = "certificate key"
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		switch {
		case bits < 2048:
			return name, "error", fmt.Sprintf("RSA-%d is below the accepted 2048-bit minimum", bits),
				"reissue with at least RSA-3072 or an elliptic-curve key"
		case bits < 3072:
			return name, "warning", fmt.Sprintf("RSA-%d (below the 3072-bit recommendation for use beyond 2030; quantum-vulnerable)", bits),
				"reissue with at least RSA-3072 and plan a post-quantum migration"
		default:
			return name, "ok", fmt.Sprintf("RSA-%d (classical strength adequate; quantum-vulnerable like all RSA)", bits), ""
		}
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		if bits < 256 {
			return name, "warning", fmt.Sprintf("ECDSA %s is below the 256-bit curve minimum", key.Curve.Params().Name),
				"reissue with P-256 or stronger"
		}
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
// certificate files are far smaller. Files over the bound are reported,
// not silently skipped.
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
// certificates, keeping the walk cheap on large trees. Content in
// unconventionally named files is out of scope and documented as such.
func isScanCandidate(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".key", ".crt", ".cer", ".cert", ".ppk", ".p12", ".pfx":
		return true
	}
	switch strings.ToLower(name) {
	case "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk":
		return true
	}
	return false
}

// scanOneFile classifies one candidate. relevant is false only when the
// file holds nothing recognizable (for example a .key file of unrelated
// data); anything that could not be safely inspected is reported.
func scanOneFile(path string) (t scanTarget, relevant bool) {
	t = scanTarget{Target: path}

	info, err := os.Lstat(path)
	if err != nil {
		t.add("access", "warning", err.Error(), "check permissions on the file")
		return t, true
	}
	if !info.Mode().IsRegular() {
		if info.Mode()&os.ModeSymlink != 0 {
			return t, false
		}
		t.add("access", "warning", "not a regular file; skipped", "")
		return t, true
	}
	if info.Size() > scanFileMax {
		t.add("access", "warning", fmt.Sprintf("file is %d bytes, over the %d-byte audit limit; not inspected", info.Size(), scanFileMax), "inspect the file manually")
		return t, true
	}

	f, err := os.Open(path)
	if err != nil {
		t.add("access", "warning", err.Error(), "check permissions on the file")
		return t, true
	}
	data, err := io.ReadAll(io.LimitReader(f, scanFileMax+1))
	f.Close()
	if err != nil {
		t.add("access", "warning", "read failed: "+err.Error(), "check the file and its filesystem")
		return t, true
	}
	defer memguard.Wipe(data)
	if len(data) > scanFileMax {
		t.add("access", "warning", "file grew past the audit limit while being read; not inspected", "inspect the file manually")
		return t, true
	}

	private := false
	found := false

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.add("certificate", "warning", "unparseable certificate block: "+err.Error(), "verify the file is intact")
				found = true
				continue
			}
			found = true
			t.add(certExpiryCheck(cert, time.Now()))
			t.add(certKeyCheck(cert))
		case block.Type == "ENCRYPTED PRIVATE KEY":
			found, private = true, true
			t.add("private key", "ok", "PKCS#8 key is passphrase-protected", "")
		case block.Type == "OPENSSH PRIVATE KEY":
			found, private = true, true
			t.add(scanOpenSSHKey(pem.EncodeToMemory(block)))
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			found, private = true, true
			if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
				t.add("private key", "ok", "legacy PEM key is passphrase-protected", "")
			} else {
				t.add("private key", "warning", "unencrypted "+block.Type+" on disk",
					"protect it with a passphrase, or seal it with sindook seal")
			}
		}
	}

	if !found {
		ext := strings.ToLower(filepath.Ext(path))
		switch {
		case strings.HasPrefix(string(data), "PuTTY-User-Key-File-"):
			found, private = true, true
			t.add(scanPuTTYKey(data))
		case looksLikeDER(data) && ext != ".p12" && ext != ".pfx":
			if cert, err := x509.ParseCertificate(data); err == nil {
				found = true
				t.add(certExpiryCheck(cert, time.Now()))
				t.add(certKeyCheck(cert))
			} else if _, err := x509.ParsePKCS8PrivateKey(data); err == nil {
				found, private = true, true
				t.add("private key", "warning", "unencrypted DER PKCS#8 private key on disk",
					"protect it with a passphrase, or seal it with sindook seal")
			}
		case ext == ".p12" || ext == ".pfx":
			found, private = true, true
			t.add("private key", "warning", "PKCS#12 container was not opened; its protection was not verified",
				"check the container's passphrase strength and contents manually")
		}
	}
	if !found {
		return t, false
	}

	if private {
		if warning := warnInsecurePerms(path, info); warning != "" {
			t.add("permissions", "warning", warning, "restrict the key file to your account")
		}
	}
	return t, true
}

func scanOpenSSHKey(pemData []byte) (name, status, detail, remediation string) {
	name = "private key"
	_, err := ssh.ParseRawPrivateKey(pemData)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return name, "ok", "OpenSSH key is passphrase-protected", ""
	case err != nil:
		return name, "warning", "unparseable OpenSSH key: " + err.Error(), "verify the file is intact"
	default:
		return name, "warning", "unencrypted OpenSSH private key on disk",
			"add a passphrase with ssh-keygen -p"
	}
}

func scanPuTTYKey(data []byte) (name, status, detail, remediation string) {
	name = "private key"
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "Encryption:"); ok {
			if strings.TrimSpace(value) == "none" {
				return name, "warning", "unencrypted PuTTY private key on disk",
					"set a passphrase in PuTTYgen, or seal it with sindook seal"
			}
			return name, "ok", "PuTTY key is passphrase-protected", ""
		}
	}
	return name, "warning", "PuTTY key without a readable Encryption header", "verify the file is intact"
}

// looksLikeDER cheaply gates DER parse attempts on the ASN.1 SEQUENCE tag
// so arbitrary binary files are not parsed as certificates or keys. Both
// short-form lengths (small keys) and long-form lengths (certificates)
// occur in practice.
func looksLikeDER(data []byte) bool {
	return len(data) > 4 && data[0] == 0x30
}
