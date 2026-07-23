package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ruddro-roy/sindook/internal/box"
)

const usageInspect = `usage: sindook inspect [-json] [FILE...]

Show the public metadata of sealed files without any credentials: format
version, key slots, and KDF parameters. This reveals nothing an attacker
holding the file does not already have. Armored input is detected
automatically. Slot metadata is covered by the header MAC, which only a
key holder can verify, so treat it as a claim until the file opens.

flags:
  -json  machine-readable output, one JSON array

example:
  sindook inspect budget.xlsx.sindook
`

type inspectReport struct {
	File          string         `json:"file"`
	Armored       bool           `json:"armored,omitempty"`
	Version       int            `json:"version"`
	HeaderSize    int64          `json:"header_size"`
	FileSize      *int64         `json:"file_size,omitempty"`
	PlaintextSize *int64         `json:"plaintext_size,omitempty"`
	Slots         []box.SlotInfo `json:"slots"`
}

func cmdInspect(args []string) error {
	fs := newFlagSet("inspect", usageInspect)
	jsonOut := fs.Bool("json", false, "")
	fs.Parse(args)

	inputs := fs.Args()
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	reports := []inspectReport{}
	var errs []error
	for _, inPath := range inputs {
		rep, err := inspectOne(inPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rep.File, err))
			continue
		}
		reports = append(reports, rep)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			errs = append(errs, err)
		}
	} else {
		for _, rep := range reports {
			printReport(rep)
		}
	}
	return errors.Join(errs...)
}

func inspectOne(inPath string) (inspectReport, error) {
	name := inPath
	if name == "" || name == "-" {
		name = "stdin"
	}
	rep := inspectReport{File: name}
	in, _, size, err := openInput(inPath)
	if err != nil {
		return rep, err
	}
	defer in.Close()

	src, armored, err := detectArmor(in)
	if err != nil {
		return rep, err
	}
	rep.Armored = armored
	info, err := box.Inspect(src)
	if err != nil {
		return rep, err
	}
	rep.Version = info.Version
	rep.HeaderSize = info.HeaderSize
	rep.Slots = info.Slots
	// Armor inflates the on-disk size, so plaintext size is only derivable
	// for binary regular files.
	if size >= 0 && !armored {
		rep.FileSize = &size
		if pt := box.PlaintextSize(size - info.HeaderSize); pt >= 0 {
			rep.PlaintextSize = &pt
		}
	}
	return rep, nil
}

func printReport(rep inspectReport) {
	encoding := ""
	if rep.Armored {
		encoding = ", armored"
	}
	fmt.Printf("%s: sindook format v%d%s\n", rep.File, rep.Version, encoding)
	switch {
	case rep.PlaintextSize != nil:
		fmt.Printf("  file %s, header %s, plaintext %s\n",
			humanBytes(*rep.FileSize), humanBytes(rep.HeaderSize), humanBytes(*rep.PlaintextSize))
	case rep.FileSize != nil:
		fmt.Printf("  file %s, header %s, payload malformed\n",
			humanBytes(*rep.FileSize), humanBytes(rep.HeaderSize))
	default:
		fmt.Printf("  header %s\n", humanBytes(rep.HeaderSize))
	}
	fmt.Printf("  %d key slot(s):\n", len(rep.Slots))
	for i, s := range rep.Slots {
		fmt.Printf("    %d. %s\n", i+1, describeSlot(rep.Version, s))
	}
}

func describeSlot(version int, s box.SlotInfo) string {
	if s.Argon != nil {
		return fmt.Sprintf("passphrase, argon2id (t=%d, m=%s, threads=%d)",
			s.Argon.Time, humanBytes(int64(s.Argon.MemoryKiB)*1024), s.Argon.Threads)
	}
	switch {
	case version == 2 && s.Type == box.SlotXWing, version == 1 && s.Type == 0x01:
		return "x-wing recipient (X25519 + ML-KEM-768)"
	default:
		return fmt.Sprintf("unknown slot type 0x%02x (%d bytes, newer format?)", s.Type, s.Body)
	}
}
