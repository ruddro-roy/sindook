package main

import (
	"testing"
)

// FuzzLoadBaseline proves the -baseline parser rejects arbitrary input
// without panicking: malformed JSON, wrong versions, duplicate or
// malformed entries must return errors, never crash a verify run.
func FuzzLoadBaseline(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"created_at":"2026-01-01T00:00:00Z","entries":[]}`))
	f.Add([]byte(`{"version":1,"entries":[{"file":"a.sindook","sha256":"abababababababababababababababababababababababababababababababab"}]}`))
	f.Add([]byte(`{"version":1,"entries":[{"file":"a","sha256":"x"},{"file":"a","sha256":"y"}]}`))
	f.Add([]byte(`{"version":9999999999}`))
	f.Add([]byte("not json at all"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := parseBaseline(raw, "")
		if err != nil {
			return
		}
		if b.Version != baselineVersion {
			t.Fatalf("accepted version %d", b.Version)
		}
		seen := map[string]bool{}
		for _, e := range b.Entries {
			if e.File == "" || len(e.SHA256) != 64 || seen[e.File] {
				t.Fatalf("accepted malformed entry %+v", e)
			}
			seen[e.File] = true
		}
	})
}
