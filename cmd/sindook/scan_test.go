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
		{arg: "", wantErr: true},
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
	ecdsaPub := &ecdsa.PublicKey{Curve: elliptic.P256()}
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
		{"ecdsa p-256", ecdsaPub, "ok"},
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

// selfSignedServer starts a local TLS server with a self-signed certificate
// for 127.0.0.1 and returns its HOST:PORT. The accept loop completes
// handshakes until the listener closes at test cleanup.
func selfSignedServer(t *testing.T, notBefore, notAfter time.Time) string {
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
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
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

func TestScanTLSTargetSelfSigned(t *testing.T) {
	now := time.Now()
	addr := selfSignedServer(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "certificate chain", "error")
	checkStatus(t, target, "hostname", "ok")
	checkStatus(t, target, "certificate expiry", "ok")
	checkStatus(t, target, "certificate key", "ok")
	checkStatus(t, target, "protocol", "ok")
	// Both sides are the local Go runtime, which negotiates the hybrid
	// post-quantum group by default.
	checkStatus(t, target, "post-quantum key exchange", "ok")
}

func TestScanTLSTargetExpired(t *testing.T) {
	now := time.Now()
	addr := selfSignedServer(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	target := scanTLSTarget(addr, 5*time.Second)

	checkStatus(t, target, "connection", "ok")
	checkStatus(t, target, "certificate chain", "error")
	checkStatus(t, target, "certificate expiry", "error")
	if target.Errors < 2 {
		t.Errorf("expired self-signed endpoint: errors = %d, want >= 2", target.Errors)
	}
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
	yes := []string{"a.pem", "b.KEY", "c.crt", "id_rsa", "id_ed25519", "d.ppk", "e.pfx"}
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
