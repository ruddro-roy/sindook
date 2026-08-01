package box

import (
	"bytes"
	"os"
	"testing"

	"github.com/ruddro-roy/sindook/xwing"
)

// Golden fixtures pin the compatibility promise: a file sealed by a released
// version opens in every later release. These are committed binaries, not
// files regenerated at test time, so a change that breaks old readers fails
// here rather than at a user.

// TestWriteV3Fixtures regenerates the committed v3 fixtures. It is skipped by
// default: regenerating them would defeat their purpose. Run it deliberately
// only when adding a new format version, never to make a failing test pass.
//
//	SINDOOK_WRITE_FIXTURES=1 go test ./internal/box -run TestWriteV3Fixtures
func TestWriteV3Fixtures(t *testing.T) {
	if os.Getenv("SINDOOK_WRITE_FIXTURES") != "1" {
		t.Skip("set SINDOOK_WRITE_FIXTURES=1 to regenerate committed fixtures")
	}
	id := fixtureIdentity(t)
	plain := []byte(fixturePlaintext)

	cases := []struct {
		name string
		opts SealOptions
	}{
		{"v3-recipient.sindook", SealOptions{Recipients: [][]byte{id.PublicKey()}}},
		{"v3-passphrase.sindook", SealOptions{Passphrases: [][]byte{[]byte(fixturePassphrase)}, Argon: testArgon}},
		{"v3-mixed.sindook", SealOptions{
			Recipients:  [][]byte{id.PublicKey()},
			Passphrases: [][]byte{[]byte(fixturePassphrase)},
			Argon:       testArgon,
		}},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		if err := SealV3(&out, bytes.NewReader(plain), tc.opts,
			ArenaOptions{SlotCapacity: minSlotCapacity, ReserveRecipients: -1}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/"+tc.name, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote testdata/%s (%d bytes)", tc.name, out.Len())
	}
}

func TestV3Fixtures(t *testing.T) {
	id := fixtureIdentity(t)
	pass := []byte(fixturePassphrase)
	want := []byte(fixturePlaintext)

	cases := []struct {
		file string
		id   *xwing.PrivateKey
		pass []byte
	}{
		{"v3-recipient.sindook", id, nil},
		{"v3-passphrase.sindook", nil, pass},
		{"v3-mixed.sindook", id, nil},
		{"v3-mixed.sindook", nil, pass},
	}
	for _, tc := range cases {
		blob, err := os.ReadFile("testdata/" + tc.file)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		got, err := openWith(t, blob, tc.id, tc.pass)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", tc.file, err)
		}

		// A committed fixture must also still rotate, which is the property
		// that would break first if the arena layout ever drifted.
		seal := SealOptions{Recipients: [][]byte{newIdentity(t).PublicKey()}}
		if tc.id == nil {
			seal = SealOptions{Passphrases: [][]byte{pass}, Argon: testArgon}
		}
		var rotated bytes.Buffer
		if err := Rewrap(&rotated, bytes.NewReader(blob), tc.id, tc.pass, seal, false); err != nil {
			t.Fatalf("%s: rotation: %v", tc.file, err)
		}
		info, err := InspectAt(bytes.NewReader(rotated.Bytes()))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if info.Arena.Generation != 2 || !info.Arena.Scrubbed {
			t.Fatalf("%s: rotation left generation %d scrubbed=%v", tc.file, info.Arena.Generation, info.Arena.Scrubbed)
		}
	}
}
