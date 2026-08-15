package main

import (
	"fmt"
	"os"

	"github.com/ruddro-roy/sindook/internal/box"
	"github.com/ruddro-roy/sindook/xwing"
)

const usageSelftest = `usage: sindook selftest

Run in-process cryptographic self-tests: re-check the X-Wing draft-10
test vectors and exercise the box format (round trip, wrong credential
rejection, and tamper detection), printing one line per check.

This is a fast sanity check, not a replacement for the full test suite.
`

func cmdSelftest(args []string) error {
	fs := newFlagSet("selftest", usageSelftest)
	parseInterspersedFlags(fs, args)
	if fs.NArg() != 0 {
		return usagef("selftest takes no arguments")
	}

	if err := xwing.SelfTest(); err != nil {
		fmt.Fprintf(os.Stderr, "sindook selftest: FAILED: %v\n", err)
		return err
	}
	fmt.Println("x-wing draft-10 vectors: ok")
	if err := box.SelfTest(); err != nil {
		fmt.Fprintf(os.Stderr, "sindook selftest: FAILED: %v\n", err)
		return err
	}
	fmt.Println("box round trip: ok")
	fmt.Println("box tamper detection: ok")
	return nil
}
