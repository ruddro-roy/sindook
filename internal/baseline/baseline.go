// Package baseline implements the restorability record behind
// verify -save/-baseline: which sealed files were proven restorable, when,
// and the exact ciphertext digests that passed.
package baseline

import (
	"encoding/json"
	"fmt"
)

// Version is the on-disk format version of a baseline record. The format
// gains fields only, following the same additive policy as the config
// file (docs/COMPATIBILITY.md).
const Version = 1

// Record is the JSON document written by -save and read by -baseline.
type Record struct {
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"`
	Entries   []Entry `json:"entries"`
}

// Entry records one file's successful verification.
type Entry struct {
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	Size       *int64 `json:"size,omitempty"`
	VerifiedAt string `json:"verified_at"`
}

// Parse validates raw baseline bytes; display names the file in errors
// ("" for anonymous input, e.g. fuzzing).
func Parse(raw []byte, display string) (Record, error) {
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, fmt.Errorf("sindook: parse baseline %s: %w", display, err)
	}
	if r.Version != Version {
		return Record{}, fmt.Errorf("sindook: unsupported baseline version %d in %s", r.Version, display)
	}
	index := make(map[string]bool, len(r.Entries))
	for _, e := range r.Entries {
		if e.File == "" || len(e.SHA256) != 64 {
			return Record{}, fmt.Errorf("sindook: baseline %s has a malformed entry", display)
		}
		if index[e.File] {
			return Record{}, fmt.Errorf("sindook: baseline %s lists %s twice", display, e.File)
		}
		index[e.File] = true
	}
	return r, nil
}
