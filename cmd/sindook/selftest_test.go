package main

import "testing"

func TestCmdSelftest(t *testing.T) {
	if err := cmdSelftest(nil); err != nil {
		t.Fatalf("selftest failed: %v", err)
	}
}
