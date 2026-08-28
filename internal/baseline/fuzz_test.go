package baseline

import (
	"testing"
)

// FuzzParseBaseline proves the -baseline parser rejects arbitrary input
// without panicking: malformed JSON, wrong versions, duplicate or
// malformed entries must return errors, never crash a verify run.
func FuzzParseBaseline(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"created_at":"2026-01-01T00:00:00Z","entries":[]}`))
	f.Add([]byte(`{"version":1,"entries":[{"file":"a.sindook","sha256":"abababababababababababababababababababababababababababababababab"}]}`))
	f.Add([]byte(`{"version":1,"entries":[{"file":"a","sha256":"x"},{"file":"a","sha256":"y"}]}`))
	f.Add([]byte(`{"version":9999999999}`))
	f.Add([]byte("not json at all"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := Parse(raw, "")
		if err != nil {
			return
		}
		if r.Version != Version {
			t.Fatalf("accepted version %d", r.Version)
		}
		seen := map[string]bool{}
		for _, e := range r.Entries {
			if e.File == "" || len(e.SHA256) != 64 || seen[e.File] {
				t.Fatalf("accepted malformed entry %+v", e)
			}
			seen[e.File] = true
		}
	})
}
