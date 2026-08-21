package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/term"

	"github.com/ruddro-roy/sindook/box"
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

	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	green := func(s string) string {
		if isTTY {
			return "\x1b[32m" + s + "\x1b[0m"
		}
		return s
	}
	red := func(s string) string {
		if isTTY {
			return "\x1b[31m" + s + "\x1b[0m"
		}
		return s
	}
	fmt.Printf("Sindook %s selftest on %s/%s\n", baseVersion(), runtime.GOOS, runtime.GOARCH)
	start := time.Now()

	if err := xwing.SelfTest(); err != nil {
		fmt.Printf("[%s] x-wing draft-10 vectors: %v\n", red("FAIL"), err)
		fmt.Fprintf(os.Stderr, "sindook selftest: FAILED: %v\n", err)
		return err
	}
	fmt.Printf("[%s] x-wing draft-10 vectors: ok\n", green("ok"))

	t0 := time.Now()
	if err := box.SelfTest(); err != nil {
		fmt.Printf("[%s] box self-test: %v (elapsed %s)\n", red("FAIL"), err, time.Since(t0).Truncate(time.Millisecond))
		fmt.Fprintf(os.Stderr, "sindook selftest: FAILED: %v\n", err)
		return err
	}
	fmt.Printf("[%s] box round trip: ok\n", green("ok"))
	fmt.Printf("[%s] box tamper detection: ok\n", green("ok"))
	fmt.Printf("selftest: all 3 checks passed (%s)\n", time.Since(start).Truncate(time.Millisecond))
	return nil
}
