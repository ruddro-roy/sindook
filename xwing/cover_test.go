package xwing

import "testing"

// TestSelfTestVectors runs the in-library runtime self test: the draft-10
// Appendix C vector and one live encapsulate/decapsulate agreement.
func TestSelfTestVectors(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
}
