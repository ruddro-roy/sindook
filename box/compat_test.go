package box

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
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

// ---- v0.9.0 fixtures -------------------------------------------------------
//
// v090-passphrase.sindook, v090-recipient.sindook, and
// v090-compressed.sindook were produced by the published v0.9.0 release
// binary (verified against the release checksums.txt before use), with:
//
//	sindook seal -passfile pass.txt -o v090-passphrase.sindook plain.txt
//	sindook seal -r id.key.pub -o v090-recipient.sindook plain.txt
//	sindook seal -z -r id.key.pub -o v090-compressed.sindook plain.txt
//
// The compressed fixture anchors the compression layer (added in v0.8.0)
// into the compatibility contract: future code must keep opening
// compressed files produced by released versions. Compression wraps the
// plaintext above the encryption layer, so the box test opens to the gzip
// stream and decompresses it here.

// v090Plaintext is the content sealed into the v0.9.0 fixtures.
const v090Plaintext = "compatibility fixture: v0.9.0\ncompression and baseline eras\n"

// v090Passphrase opens v090-passphrase.sindook. TEST-ONLY.
const v090Passphrase = "fixture-passphrase-v090"

// v090IdentityB64 is the base64 of the TEST-ONLY v0.9.0 identity file
// that opens v090-recipient.sindook and v090-compressed.sindook. It lives
// here because *.key files are gitignored by design.
const v090IdentityB64 = `IyBzaW5kb29rIGlkZW50aXR5LCBjcmVhdGVkIDIwMjYtMDgtMjhUMDk6MDc6NTRa
CiMgcHVibGljOiBzaW5kb29rcGsxOmhyUllCL1plSGJiRXpXZ1EyMW9jQk9wM3Yr
ckRiOGV0YlVCYTNwcTlzZWswcmpTczQ1QjJYOVdTSktOMXNyVTJ6bForcnNaQXNp
Rms1amd0cmpkTjJyaW9FbEpGTXNodVM2SWwySEE5Ly9hMTlmT0hURmNGd2dNSUV0
aGg1K0lpME1sYW94Z2dnd0d4bUR4R0UvTnBCK05yVDlLVDc2Zk9SYWdqMmt2UEI4
S2ZNVEVLdWNraVZjQWc5cU5MbjBKRWUybFRmUm9LRUJwMEtpbC9udWNLanBSZHNY
TmFOUGZQNVlhby82QUovbHpIS21VbDBpZDhTck5FeXJkZ3NreDY1RlJOS0dzcVZQ
bU5MRldqQzhhQkxncFN3dnh0M3hBVEZwWWlkUEtNVkxZU0VtTU9PcVZpakZ5RVJC
UkhJWVVDV0htSzRSTUFGb3VWMWtxZW8vazlqM0lyemJPWjFpUWxzVkpxM2lpdEk2
cEZTL3RTaUxJS3duZXRhVE5zNjhRcS9Dd3N0S0VLNDh0SlJpR2FRa09oak1oV1Q0
Y0trRnAyblBLVDYvU0JXZkd4MEZDdXlXUURNSW8zNDZCSjMyTE9OcW8vTHl5Z0ll
a0NBYUd3QnRMS01OTTlTY0JyWkZpeVRkeVZueE9NdGdJQTlSZWZTalF6djlkVnFi
T2ZETEZ6cFN5cmhCaThMSU1rN0V0eW5JZ1hybXVJTEttcVVKaDVxcEFSWGRNUktI
RnI2NVZjdlFlOFUzVEMxdW0rOHJXczRuWTNJY2VvVHd3NFhmeU54TFl1djVNZEpz
QVREVXVXM1NaRnVQRm9vNXlZblVtM2lzZDJNenVSWmZFRERpeWptOGRWdmtvYW9v
b1JpUWdhS3BBT080VEp2ZVI4WUVOV0JKUWpVaFNuQkxJeitHRnBybXV3WXNGSjho
d1ZpRVF6bDlJei9GaWxOZEF2dExwZi9NdzlWcmVOSjNDVko0Sk5wUXlTTTRHY3VO
TzhlMVlFejJwK3BqUmJ6T1dyRktKa3VIcFNDY1Y0ZDVWcFdqWkZQQnBLN0dOZVd5
Y2pXRWtVZEZ5ZTk2aUZBUlp1S01GYXppaThjQWhvQ3dUREtrTEhQblZubllVNE05
cSt0RFFwNHJpSjJ2R0RnN3duZ3V4Tm03aFQybVlHUEJoMUhEbVc1RmU4ZUZ1cllZ
czQ1S1Fod2tkYzFFWlZjdWJBeDNLY1owSVBnSUdTVDNrVzM5VVhtU1VDU3V4OXB1
RzhaV3lRenp1TXQyc2cwT1dCaTZTazdvTUVjdnNUei9POC9qeGp5VkhMTDdtK3RY
T01Id1FCZ2tIT0pYeUFWdkVhQXVtajd6cW9qbFNUMWhXKzBhaTFxckVKdXRKMWg0
aHFwK2R4emJzRlNIa2ZIbktrRzZ2REMybGNkNWdsM2hnUU1mbEVzcm00M0NreVJ4
Z1NNa1lETDZnQnI1ak4vZms2OGRtMzM4UWFTSWlzdWF4UmFzd2pYMEpkZWljWVhJ
RVFqdUpEVDdvaGNHSExxY2UrVUNBNGs4cUZacnFEd0hDUDdlTVNMR0dCa2FodWtP
TzA1NXBMOFRhZ0c5QjNFT1djYWVuQ3hWZXpEd3ZOU3JWR0JtVit0eVRCRHlrdkt0
cHI2VUdTZVVGamRJS2xQT3gzdzdHUlh2eHZvTUUzQ3J1R3htTElUcE9xUlZhVnpu
bGt2Tnd6bTZmSE52ZU1pWnFjTUJvUUFTZU92Q09hQU5LU0hRVjVFbGRiUHFxS2xX
ZkZLSFVsTnNuTmZNS2J2d3FBTzdLM3VkZTgxQ1FwMHV1NisxeTR4Rm9GblNDbnRl
eTBpNnhvSjZnSnFSVStQV3N2cjhWR0xJb1VkalJJMTVMQWMxUW1FNWd5QVFLVndM
Y1JTMVU2bU5aelRWU25SdUN0aDFacnRvZXJ2S1lmMVBrQlk0SEF1N0Y1UDZ1dXpQ
ZW5Ia0d0cGVIT1dJTmFIanlTdktXbno5Y20vd3c1SU9zWjFFWnh6SWkzNmJNdWV4
YVl4Zm9uV0xKczlsZE15bkJ4Z010RzdJdjlmYTBIQ3VzdUVJcHhFWDNXcmZ4QUlv
K2ZKdTBoK3luQnEvYjYrWjZVbEpocWs2NWNBeUV6QVZmYmF0QmFBOUdQN3M5NVBZ
Y0pUTTZVQ2pqK0Z3CnNpbmRvb2tzazE6UFdNdGJFYlF4QnMrbDlXTkkwYWZwVVlt
d0t2U2RmU3JMSU5SK3FMbk5UZwo=`

// v090IdentityKey materializes the embedded v0.9.0 identity and parses
// it the same way the CLI does.
func v090IdentityKey(t *testing.T) *xwing.PrivateKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v090IdentityB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v090-id.key")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
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
			t.Fatalf("embedded v0.9.0 identity is malformed: %v", err)
		}
		key, err := xwing.NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	t.Fatal("embedded v0.9.0 identity has no sindooksk1: entry")
	return nil
}

// TestV090Fixtures proves current code opens every fixture produced by
// the published v0.9.0 binary: plain, recipient, and compressed paths,
// with negative cases so the fixtures cannot pass through a lenient path.
func TestV090Fixtures(t *testing.T) {
	id := v090IdentityKey(t)

	t.Run("passphrase", func(t *testing.T) {
		blob, err := os.ReadFile("testdata/v090-passphrase.sindook")
		if err != nil {
			t.Fatal(err)
		}
		out, err := openWith(t, blob, nil, []byte(v090Passphrase))
		if err != nil {
			t.Fatalf("v0.9.0 passphrase fixture: %v", err)
		}
		if !bytes.Equal(out, []byte(v090Plaintext)) {
			t.Fatalf("v0.9.0 passphrase fixture plaintext = %q, want %q", out, v090Plaintext)
		}
	})

	t.Run("recipient", func(t *testing.T) {
		blob, err := os.ReadFile("testdata/v090-recipient.sindook")
		if err != nil {
			t.Fatal(err)
		}
		out, err := openWith(t, blob, id, nil)
		if err != nil {
			t.Fatalf("v0.9.0 recipient fixture: %v", err)
		}
		if !bytes.Equal(out, []byte(v090Plaintext)) {
			t.Fatalf("v0.9.0 recipient fixture plaintext = %q, want %q", out, v090Plaintext)
		}
	})

	t.Run("compressed", func(t *testing.T) {
		blob, err := os.ReadFile("testdata/v090-compressed.sindook")
		if err != nil {
			t.Fatal(err)
		}
		gz, err := openWith(t, blob, id, nil)
		if err != nil {
			t.Fatalf("v0.9.0 compressed fixture: %v", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatalf("v0.9.0 compressed fixture is not gzip: %v", err)
		}
		out, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("v0.9.0 compressed fixture gunzip: %v", err)
		}
		if !bytes.Equal(out, []byte(v090Plaintext)) {
			t.Fatalf("v0.9.0 compressed fixture plaintext = %q, want %q", out, v090Plaintext)
		}
	})

	// Negative cases: wrong credentials must still fail.
	passBlob, err := os.ReadFile("testdata/v090-passphrase.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWith(t, passBlob, nil, []byte("wrong")); err == nil {
		t.Fatal("v0.9.0 passphrase fixture opened with a wrong passphrase")
	}
	recBlob, err := os.ReadFile("testdata/v090-recipient.sindook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWith(t, recBlob, newIdentity(t), nil); err == nil {
		t.Fatal("v0.9.0 recipient fixture opened with a stranger identity")
	}
}
