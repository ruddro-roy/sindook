package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// TestResolveVersion pins the version-resolution table: a release linker
// stamp wins first, then real release tags in the module build info win over
// the development default. Pseudo-versions (v0.0.0-20240101...-abc) and
// "(devel)" deliberately fall back to the dev default so only tagged builds
// report a release version.
func TestResolveVersion(t *testing.T) {
	dev := "0.7.1-dev"
	for _, tc := range []struct {
		name       string
		bi         *debug.BuildInfo
		devDefault string
		want       string
	}{
		{"nil build info falls back", nil, dev, dev},
		{"devel falls back", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, dev, dev},
		{"empty main version falls back", &debug.BuildInfo{}, dev, dev},
		{"v0.7.1 tag wins", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1"}}, dev, "0.7.1"},
		{"plain 0.7.1 tag wins", &debug.BuildInfo{Main: debug.Module{Version: "0.7.1"}}, dev, "0.7.1"},
		{"rc prerelease wins", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1-rc1"}}, dev, "0.7.1-rc1"},
		{"uppercase prerelease wins", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1-RC2"}}, dev, "0.7.1-RC2"},
		{"pseudo-version falls back", &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20240101120000-abc123def"}}, dev, dev},
		{"devel with VCS settings falls back",
			&debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
					{Key: "vcs.time", Value: "2026-08-16T00:00:00Z"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			dev,
			dev},
		{"two-part version falls back", &debug.BuildInfo{Main: debug.Module{Version: "v0.7"}}, dev, dev},
		{"build metadata falls back", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1+build"}}, dev, dev},
		{"branch name falls back", &debug.BuildInfo{Main: debug.Module{Version: "main"}}, dev, dev},
		{"custom dev default passes through", nil, "9.9.9", "9.9.9"},
		{"linker stamp beats module tag", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1"}}, "9.9.9", "9.9.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.devDefault, tc.bi); got != tc.want {
				t.Errorf("resolveVersion(%q, %v) = %q, want %q", tc.devDefault, tc.bi, got, tc.want)
			}
		})
	}
}

// buildTestBinary compiles the real sindook binary from this module into
// dir, optionally stamping main.version with -ldflags, and returns the
// binary path. It is deterministic (local toolchain only, no network) but
// takes a few seconds, so -short mode skips it. It must not run in
// parallel with itself; the package suite has no parallel tests.
func buildTestBinary(t *testing.T, dir, ldflags string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	bin := filepath.Join(dir, "sindook")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	args := []string{"build", "-o", bin}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, ".")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("go build timed out: %v\n%s", err, out)
		}
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runBinary runs the compiled test binary and returns its combined output.
func runBinary(t *testing.T, bin string, extraEnv []string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("%s %v timed out: %v", bin, args, err)
		}
		t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
	}
	return string(out)
}

// runBinaryVersion runs "<bin> version" and returns the first output line.
func runBinaryVersion(t *testing.T, bin string) string {
	t.Helper()
	out := runBinary(t, bin, nil, "version")
	line, _, _ := strings.Cut(out, "\n")
	return line
}

// TestBuildVersionLinkerStamp builds the real binary with
// -X main.version=9.9.9 and requires "sindook version" to report exactly
// the stamped version. This is the goreleaser path: the linker override
// wins over both module build info and the dev default.
func TestBuildVersionLinkerStamp(t *testing.T) {
	bin := buildTestBinary(t, t.TempDir(), "-X main.version=9.9.9")
	got := runBinaryVersion(t, bin)
	if !strings.HasPrefix(got, "sindook 9.9.9") {
		t.Errorf("stamped version output = %q, want prefix %q", got, "sindook 9.9.9")
	}
	if strings.HasPrefix(got, "sindook 0.7.1") {
		t.Errorf("stamped version output = %q, must not fall back to the dev default", got)
	}

	selftest := runBinary(t, bin, nil, "selftest")
	if !strings.Contains(selftest, "Sindook 9.9.9 selftest") {
		t.Errorf("stamped selftest output = %q, want stamped version in header", selftest)
	}

	doctorOut := runBinary(t, bin, []string{"SINDOOK_CONFIG_DIR=" + t.TempDir()}, "doctor", "-json")
	var report doctorReport
	if err := json.Unmarshal([]byte(doctorOut), &report); err != nil {
		t.Fatalf("stamped doctor JSON did not parse: %v\n%s", err, doctorOut)
	}
	if report.Version != "9.9.9" {
		t.Errorf("stamped doctor version = %q, want %q", report.Version, "9.9.9")
	}
}

// TestBuildVersionDevDefault builds the real binary with no linker flags
// from this source tree and requires "sindook version" to report the
// source-tree dev default plus VCS provenance. This is the developer-build path.
func TestBuildVersionDevDefault(t *testing.T) {
	bin := buildTestBinary(t, t.TempDir(), "")
	got := runBinaryVersion(t, bin)
	if want := "sindook " + version; !strings.HasPrefix(got, want) {
		t.Errorf("dev build version output = %q, want prefix %q", got, want)
	}
}

// The true end-to-end tagged-module case (no linker flags, module build
// info Main.Version="v0.7.1") cannot be reproduced from an untagged
// checkout: go build always records "(devel)" or a pseudo-version here.
// It is covered by the resolveVersion unit table above, and is verified
// against the real binary after tagging with:
//
//	go install github.com/ruddro-roy/sindook/cmd/sindook@v0.7.1
//	sindook version   # must print "sindook 0.7.1"
