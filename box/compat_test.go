package box

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// Compatibility fixtures: v060-passphrase.sindook and
// v060-recipient.sindook were produced by the real v0.6.0 binary built
// from the v0.6.0 tag (git archive v0.6.0, go build ./cmd/sindook), with
// the commands
//
//	sindook seal -passfile pass.txt -o v060-passphrase.sindook plain.txt
//	sindook keygen -o id.key
//	sindook seal -r id.key.pub -o v060-recipient.sindook plain.txt
//
// so v0.7.0 proves it still reads every file produced by the previous
// supported release. The plaintext is v060Plaintext below.

// v060Plaintext is the content sealed into the v0.6.0 fixtures.
const v060Plaintext = "compatibility fixture: v0.6.0 -> v0.7.0\n"

// v060Passphrase opens v060-passphrase.sindook. TEST-ONLY, never used
// outside this test.
const v060Passphrase = "fixture-passphrase"

// v060IdentityB64 is the base64 encoding of the TEST-ONLY v0.6.0 identity
// file (id.key) that opens v060-recipient.sindook. It lives in this test
// because *.key files are gitignored by design; it must never be used
// outside these fixtures.
const v060IdentityB64 = `
		IyBzaW5kb29rIGlkZW50aXR5LCBjcmVhdGVkIDIwMjYtMDgtMTZUMDQ6Mjk6MjhaCiMgcHVibGlj
		OiBzaW5kb29rcGsxOkZBdzRGWEdicXJVcTlDdGJscFNuOFNhRlVlZTZXc0VYR0doZVloRXoxdm8r
		SnZLaHVvaUZubWZCWjdGVnliVS9SSVc0aWxKcjNYbTJiT1pOYi9kYktoWE53UWlDVktTRHQzT2pI
		TUlPUDJLa1BSSkZ2eUdyZ2VwMHpVbE55aVJDOTNvdC9WZU9wTUlSTE9PRStLUE9xbXpKd3JjbDlO
		aFNleUJqTklVZS9zT0U5K3c4MEVCSDNUcFFzT05hUS9tK0Zyd2ExSlJNVXRpWEUyWUQydmFXSTdz
		MWprR05oQk83aDZvOEd2eEtsZ2w2Y2hoZ1lYaTE0bmR0QjRwOGZQTzd2RFVDWVNxNDJmTERMZlc2
		bXBHMmM5YXlmdWxCbHZXZTdWS2RheEt1bnBYRzBXQWZRR1ZhZTFJa3RKQkN6VU1OaUxVV0V0TXFi
		WHNXR1V0NlVIZHo3b0ljOVBZSU5NV1R1d3VTYVZXM1VWTjkyS0ZEY256RGQzaGVEMGk1SG13Zldl
		QXNMaW9KWEhjZ0Q0VURVUFV0bGZNVUVRcGlFTVU2VW13UEpvVU5reEJKbTFJZnBrQ0s0UlM4NTZB
		Q2ZabkcyMk95NmdVQmcrZEJWUklBU0NFa0xaaDF5dFVVQ2d4cm9QY2hmR0lBdEV4K1hweEQ1WmNu
		b1hBb0pHV1JOb2hVS1BSN1VXY0lRYW9OSDdPamRUREREZWVFdWd5TVB3TnVrWUkzNERwNjZSQTRu
		UkNqc0RaY0F6aEVMa3d4K3NMSTMxeXhzbllDQ1ZZMXpNV0dOSVJPbEdCTXQycGUwNWlQQ05iTE5u
		WUVBb0tpejJaMlU3RWpubEVxK3J2SWJ6U1ZNOUtHeTJDNVp4aFQ5NXlLODV5ZlBTWWg3UkE1T0NZ
		di9tV3JramdMazhza0pyY3BNa0U4NTlPczlKTEJ5NGx6b1ZDVnVCakpXQ0tyZWpNWm9OZk5qalpt
		eDhkaGU5RTBBYVVZdHlZSW5CdVExamVJckhnSWVxdHBEM1BPMzNBUEYyV1pEcVNMOUtXcktERlUz
		WHFPNW13Ry9kQUFCNFpUY1ZQR0s0U0x4aW9xUEtoVnZRa0RGUk5teTFoZFI2dURNaVlyQjRGd1Q2
		d284NVlyQTdBV0xFdW5vTEZXTFZkOXhZdGt2cWUyaE9zUDgyeCtnZ2R2ZG5jZlpKZCtnOEtHaXJj
		SzhjdE5GalU2T1BsZGtkQ2IwY2hjdVVmRllIVkRUTXcwb21STTZibC9kWVpwK0dJb2FWeW9jWkNH
		bm5XVzNRSWhYb0ttSmpOM3l3RUthdWRPZGt1aTdFdVg4WGdaNTlTS0VTdzFmaFZ0ek9odGJjcHE2
		U05aRVJvU0g0SzdXMVlFOU1FYmFzcGM2YnNsbEFsNkt1U1JTWVFrbnhLUFQ0Q2Yzd1F1TzFDM2Fm
		eFZWcGZIRlZCeHFETkdybGlnbmpHTmZkaFRBVW04Y0xvQktUdDV6b09WMVBiRDFieUxEM3ErbXVD
		WG9RUjc2YWx6OEhvRzh1eXowUGlpRFFFQzA3bXV4Nnl6SnpxMGxzc1N5Tk83NXdaTGVGaGFyVkVv
		RVdCbjhxa0xQL09xVEtwblJkb0hkQ0xIY3pkRHB2Qlg3OEZxbVVLYmZRQzg3eUlHU21jYWdOQ0dU
		UWsyMzNMRW5GdDFTWnVObllCNDczSzBGT1cvSlhnbkl6TnI1bXV5SlROM2FmUzMwN0dyMUJpOXFE
		TzIxaVEyay9CNElYaVgzcmtjaldnNWd4WjNXR09wQVZBM3JmQ1dJZFNhbmpKSjNqUjR2V2pIdDZV
		ZEJNQlM2RHE4amFITzlFT1lvZ2gwaEdlektBWExTUU1ndit3TmVzUTlzaEpFNFVPeTkvVjJTTmFO
		Z2VkWGMwYUkxRk1ud1JLRDFLd3RwZVUyZndOVWRGREFMNGdDWkVWdFlnVEF3L0djek5veWd4Vitl
		ekN6K0VKeWRJTS9JQ3VDRWxPSUE2d0pSY3lwVENhTmJrWUtXQUFsSjdsUS9wbFJHVmxzZ0d0ZGJz
		R2h1MW15SDRRSllKTm4rUlJZQUZLZnkwRkJoRWZZTE1wbU5HRU5rTmZHdUMxWkw4cXJ4VHhUamFK
		U3FhM1JKUXBoamlLMmlZekhzSFlkWHFKUWNBNE5ma1BacmFFUE5nCnNpbmRvb2tzazE6YTJBNlQr
		MHZkL3JNSlZUVTJUYmVDOHFDMjRRWWhVcnpWNTZod2lmbGV2awo=
`

// v060Identity writes the embedded v0.6.0 identity to dir and returns its
// path, so the private key never needs to be committed as a file.
func v060Identity(t *testing.T, dir string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v060IdentityB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	path := dir + "/v060-id.key"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// v060IdentityKey materializes the embedded v0.6.0 identity in a test
// temp directory (so no *.key file is ever committed) and parses it the
// same way the CLI does: the sindooksk1: line carries the base64 seed.
func v060IdentityKey(t *testing.T) *xwing.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(v060Identity(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "sindooksk1:") {
			continue
		}
		seed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, "sindooksk1:"))
		if err != nil || len(seed) != xwing.SeedSize {
			t.Fatalf("embedded v0.6.0 identity is malformed: %v", err)
		}
		key, err := xwing.NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	t.Fatal("embedded v0.6.0 identity has no sindooksk1: entry")
	return nil
}

// TestV060Fixtures proves that v0.7.0 opens every fixture produced by the
// released v0.6.0 binary, for both the passphrase and the recipient slot
// path.
func TestV060Fixtures(t *testing.T) {
	passBlob, err := os.ReadFile("testdata/v060-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}
	out, err := openWith(t, passBlob, nil, []byte(v060Passphrase))
	if err != nil {
		t.Fatalf("v0.6.0 passphrase fixture: %v", err)
	}
	if !bytes.Equal(out, []byte(v060Plaintext)) {
		t.Fatalf("v0.6.0 passphrase fixture plaintext = %q, want %q", out, v060Plaintext)
	}

	recBlob, err := os.ReadFile("testdata/v060-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	id := v060IdentityKey(t)
	out, err = openWith(t, recBlob, id, nil)
	if err != nil {
		t.Fatalf("v0.6.0 recipient fixture: %v", err)
	}
	if !bytes.Equal(out, []byte(v060Plaintext)) {
		t.Fatalf("v0.6.0 recipient fixture plaintext = %q, want %q", out, v060Plaintext)
	}

	// A wrong passphrase and a stranger identity must still fail, so the
	// fixtures are not just being opened through some lenient path.
	if _, err := openWith(t, passBlob, nil, []byte("wrong")); err == nil {
		t.Fatal("v0.6.0 passphrase fixture opened with a wrong passphrase")
	}
	if _, err := openWith(t, recBlob, newIdentity(t), nil); err == nil {
		t.Fatal("v0.6.0 recipient fixture opened with a stranger identity")
	}
}

// TestCurrentFormatRoundTrip seals and opens the v0.6.0 plaintext with the
// current v0.7.0 code for contrast with the frozen fixtures above.
func TestCurrentFormatRoundTrip(t *testing.T) {
	id := newIdentity(t)
	blob := sealTo(t, []byte(v060Plaintext), SealOptions{Recipients: [][]byte{id.PublicKey()}})
	out, err := openWith(t, blob, id, nil)
	if err != nil || !bytes.Equal(out, []byte(v060Plaintext)) {
		t.Fatalf("current-format round trip: %v", err)
	}
	blob = sealTo(t, []byte(v060Plaintext), SealOptions{Passphrases: [][]byte{[]byte(v060Passphrase)}, Argon: testArgon})
	out, err = openWith(t, blob, nil, []byte(v060Passphrase))
	if err != nil || !bytes.Equal(out, []byte(v060Plaintext)) {
		t.Fatalf("current-format passphrase round trip: %v", err)
	}
}
