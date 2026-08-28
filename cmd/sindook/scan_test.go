package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSplitScanTarget(t *testing.T) {
	tests := []struct {
		arg     string
		addr    string
		sni     string
		wantErr bool
	}{
		{arg: "example.com", addr: "example.com:443", sni: "example.com"},
		{arg: "example.com:8443", addr: "example.com:8443", sni: "example.com"},
		{arg: "127.0.0.1:993", addr: "127.0.0.1:993", sni: "127.0.0.1"},
		{arg: "[::1]:443", addr: "[::1]:443", sni: "::1"},
		{arg: "[::1]", addr: "[::1]:443", sni: "::1"},
		{arg: "2001:db8::1", addr: "[2001:db8::1]:443", sni: "2001:db8::1"},
		// A valid IPv6 literal that looks like host:port; the brackets
		// requirement exists precisely because this is ambiguous, and the
		// literal reading wins.
		{arg: "2001:db8::1:443", addr: "[2001:db8::1:443]:443", sni: "2001:db8::1:443"},
		{arg: "", wantErr: true},
		{arg: "example.com:", wantErr: true},
		{arg: "example.com:bad", wantErr: true},
		{arg: "example.com:70000", wantErr: true},
		{arg: "host:name:443", wantErr: true},
	}
	for _, tt := range tests {
		addr, sni, err := splitScanTarget(tt.arg)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitScanTarget(%q): want error, got %q %q", tt.arg, addr, sni)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitScanTarget(%q): %v", tt.arg, err)
			continue
		}
		if addr != tt.addr || sni != tt.sni {
			t.Errorf("splitScanTarget(%q) = %q, %q; want %q, %q", tt.arg, addr, sni, tt.addr, tt.sni)
		}
	}
}

func TestCertExpiryCheck(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		status    string
	}{
		{"expired", now.Add(-400 * day), now.Add(-day), "error"},
		{"not yet valid", now.Add(day), now.Add(400 * day), "error"},
		{"expiring soon", now.Add(-100 * day), now.Add(10 * day), "warning"},
		{"thirty days exactly", now.Add(-100 * day), now.Add(30 * day), "warning"},
		{"healthy", now.Add(-100 * day), now.Add(200 * day), "ok"},
	}
	for _, tt := range tests {
		cert := &x509.Certificate{NotBefore: tt.notBefore, NotAfter: tt.notAfter}
		_, status, detail, _ := certExpiryCheck(cert, now)
		if status != tt.status {
			t.Errorf("%s: status = %q (%s), want %q", tt.name, status, detail, tt.status)
		}
	}
}

func TestCertKeyCheck(t *testing.T) {
	rsaKey := func(bits int) *rsa.PublicKey {
		return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		key    any
		status string
	}{
		{"rsa 1024", rsaKey(1024), "error"},
		{"rsa 2048", rsaKey(2048), "warning"},
		{"rsa 3072", rsaKey(3072), "ok"},
		{"rsa 4096", rsaKey(4096), "ok"},
		{"ecdsa p-224", &ecdsa.PublicKey{Curve: elliptic.P224()}, "warning"},
		{"ecdsa p-256", &ecdsa.PublicKey{Curve: elliptic.P256()}, "ok"},
		{"ed25519", edPub, "ok"},
	}
	for _, tt := range tests {
		cert := &x509.Certificate{PublicKey: tt.key}
		_, status, detail, _ := certKeyCheck(cert)
		if status != tt.status {
			t.Errorf("%s: status = %q (%s), want %q", tt.name, status, detail, tt.status)
		}
	}
}

func TestTLSVersionCheck(t *testing.T) {
	tests := []struct {
		version uint16
		status  string
	}{
		{tls.VersionTLS13, "ok"},
		{tls.VersionTLS12, "ok"},
		{tls.VersionTLS10, "error"},
	}
	for _, tt := range tests {
		_, status, _, _ := tlsVersionCheck(tt.version)
		if status != tt.status {
			t.Errorf("version %#x: status = %q, want %q", tt.version, status, tt.status)
		}
	}
}

func TestScanSafe(t *testing.T) {
	got := scanSafe("evil\x1b[2Kname\r\n\tok")
	want := "evil?[2Kname??\tok"
	if got != want {
		t.Errorf("scanSafe = %q, want %q", got, want)
	}
}

// scanTestServer starts a local TLS server with a self-signed ECDSA P-256
// certificate for 127.0.0.1 and returns its HOST:PORT. mutate adjusts the
// server tls.Config before listening. The accept loop completes
// handshakes until the listener closes at test cleanup.
func scanTestServer(t *testing.T, notBefore, notAfter time.Time, mutate func(*tls.Config)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scan-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func checkStatus(t *testing.T, target scanTarget, name, want string) {
	t.Helper()
	for _, check := range target.Checks {
		if check.Name == name {
			if check.Status != want {
				t.Errorf("%s: status = %q (%s), want %q", name, check.Status, check.Detail, want)
			}
			return
		}
	}
	t.Errorf("%s: check missing from report %+v", name, target.Checks)
}

func checkDetailContains(t *testing.T, target scanTarget, name, substr string) {
	t.Helper()
	for _, check := range target.Checks {
		if check.Name == name {
			if !strings.Contains(strings.ToLower(check.Detail), strings.ToLower(substr)) {
				t.Errorf("%s: detail = %q, want it to mention %q", name, check.Detail, substr)
			}
			return
		}
	}
	t.Errorf("%s: check missing from report %+v", name, target.Checks)
}

func TestScanTLSTargetSelfSigned(t *testing.T) {
	now := time.Now()
	addr := scanTestServer(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil)
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "certificate chain", "error")
	checkStatus(t, target, "hostname", "ok")
	checkStatus(t, target, "certificate expiry", "ok")
	checkStatus(t, target, "certificate key", "ok")
	checkStatus(t, target, "protocol", "ok")
	// The Go test server refuses TLS 1.0/1.1 with an alert, which is
	// positive evidence of rejection.
	checkStatus(t, target, "legacy protocols", "ok")
	// Both sides are the local Go runtime, which negotiates a hybrid
	// post-quantum group by default.
	checkStatus(t, target, "post-quantum key exchange", "ok")
}

func TestScanTLSTargetExpired(t *testing.T) {
	now := time.Now()
	addr := scanTestServer(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil)
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "certificate expiry", "error")
}

func TestScanTLSTargetClassicalOnly(t *testing.T) {
	now := time.Now()
	addr := scanTestServer(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), func(cfg *tls.Config) {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	})
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "protocol", "ok")
	// The server can only do classical X25519; the hybrid-only offer must
	// be refused and reported as a warning, not an ok and not an error.
	checkStatus(t, target, "post-quantum key exchange", "warning")
	checkDetailContains(t, target, "post-quantum key exchange", "hybrid")
}

func TestScanTLSTargetLegacyOnly(t *testing.T) {
	now := time.Now()
	addr := scanTestServer(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS11
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	})
	target := scanTLSTarget(addr, 5*time.Second)

	// A legacy-only endpoint is a finding, not an unreachable host.
	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "protocol", "error")
	checkDetailContains(t, target, "protocol", "TLS 1.2 handshake failed")
}

func TestScanTLSTargetLegacyAccepted(t *testing.T) {
	now := time.Now()
	addr := scanTestServer(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS10
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		}
	})
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	// The server accepts modern TLS and also completes a TLS 1.0/1.1
	// handshake, which must surface as a legacy warning.
	checkStatus(t, target, "legacy protocols", "warning")
}

func TestScanTLSTargetUnreachable(t *testing.T) {
	// Reserve a port and close it so the dial is refused quickly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	target := scanTLSTarget(addr, 2*time.Second)
	checkStatus(t, target, "connection", "error")
}

func writeScanFixture(t *testing.T, dir, name string, data []byte, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanOneFile(t *testing.T) {
	dir := t.TempDir()

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	plainPKCS8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	plainSSH, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	sealedSSH, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "scan-files-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	puttyPlain := []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: test\n")
	mixedPEM := append(append([]byte(nil), certPEM...), pem.EncodeToMemory(plainSSH)...)

	tests := []struct {
		name       string
		file       string
		data       []byte
		check      string
		status     string
		irrelevant bool
	}{
		{name: "unencrypted pkcs8", file: "server.key", data: plainPKCS8, check: "private key", status: "warning"},
		{name: "unencrypted openssh", file: "id_ed25519", data: pem.EncodeToMemory(plainSSH), check: "private key", status: "warning"},
		{name: "encrypted openssh", file: "id_ecdsa", data: pem.EncodeToMemory(sealedSSH), check: "private key", status: "ok"},
		{name: "expiring certificate", file: "tls.crt", data: certPEM, check: "certificate expiry", status: "warning"},
		{name: "unencrypted putty", file: "login.ppk", data: puttyPlain, check: "private key", status: "warning"},
		{name: "der certificate", file: "ca.cer", data: certDER, check: "certificate expiry", status: "warning"},
		{name: "der pkcs8", file: "raw.key", data: pkcs8, check: "private key", status: "warning"},
		{name: "cert then openssh key", file: "bundle.pem", data: mixedPEM, check: "private key", status: "warning"},
		{name: "pkcs12 not opened", file: "backup.p12", data: []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}, check: "private key", status: "warning"},
		{name: "unrelated data", file: "license.key", data: []byte("AAAA-BBBB-CCCC"), irrelevant: true},
	}
	for _, tt := range tests {
		path := writeScanFixture(t, dir, tt.file, tt.data, 0o600)
		target, relevant := scanOneFile(path)
		if tt.irrelevant {
			if relevant {
				t.Errorf("%s: relevant = true, want false (%+v)", tt.name, target.Checks)
			}
			continue
		}
		if !relevant {
			t.Errorf("%s: relevant = false, want true", tt.name)
			continue
		}
		checkStatus(t, target, tt.check, tt.status)
	}
}

func TestScanOneFileOversized(t *testing.T) {
	dir := t.TempDir()
	path := writeScanFixture(t, dir, "huge.pem", make([]byte, scanFileMax+1), 0o600)
	target, relevant := scanOneFile(path)
	if !relevant {
		t.Fatal("relevant = false, want true: oversized files must be reported, not skipped")
	}
	checkStatus(t, target, "access", "warning")
	checkDetailContains(t, target, "access", "not inspected")
}

func TestScanOneFileSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	real := writeScanFixture(t, dir, "real.pem", []byte("data"), 0o600)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, relevant := scanOneFile(link); relevant {
		t.Error("symlink: relevant = true, want false")
	}
}

func TestScanOneFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics")
	}
	dir := t.TempDir()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	path := writeScanFixture(t, dir, "exposed.pem", data, 0o644)
	target, relevant := scanOneFile(path)
	if !relevant {
		t.Fatal("relevant = false, want true")
	}
	checkStatus(t, target, "permissions", "warning")
}

func TestIsScanCandidate(t *testing.T) {
	yes := []string{"a.pem", "b.KEY", "c.crt", "id_rsa", "id_ed25519", "id_ed25519_sk", "d.ppk", "e.pfx", "f.cert"}
	no := []string{"main.go", "README.md", "keyboard.txt", "id_rsa.pub.txt"}
	for _, name := range yes {
		if !isScanCandidate(name) {
			t.Errorf("isScanCandidate(%q) = false, want true", name)
		}
	}
	for _, name := range no {
		if isScanCandidate(name) {
			t.Errorf("isScanCandidate(%q) = true, want false", name)
		}
	}
}
