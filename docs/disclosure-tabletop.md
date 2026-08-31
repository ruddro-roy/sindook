# Disclosure tabletop

This is a paper exercise, run 2026-08-31, walking one hypothetical
vulnerability end to end through the policy in
[SECURITY.md](../SECURITY.md). It exists so the disclosure process has
been thought through and written down before it is ever needed. It is
not evidence of a real vulnerability; no such report exists. Until a
real incident exercises this path, it stays a documented procedure, not
a claim of readiness.

## The scenario

A researcher privately reports: on all released versions, a malformed
slot length in a hostile sealed file causes the fast rewrap path to
copy payload bytes from beyond the authenticated region into the
replacement file. Impact class: plaintext disclosure of adjacent file
content under attacker-crafted input, requiring the victim to run
rewrap on an attacker-supplied file. Severity if confirmed: high.

## Walkthrough, step by step

1. **Intake.** The report arrives through GitHub private vulnerability
   reporting, as SECURITY.md directs. The maintainer reads it, replies
   within the same week confirming receipt, and asks for a
   proof-of-concept file with synthetic plaintext if the reproduction
   is ambiguous. Nothing about the report appears in public issues,
   commits, or chat.
2. **Triage.** The maintainer reproduces against the latest release
   with synthetic data, then `git bisect` on the payload-copy path in
   `box/` to find the introducing change and the affected releases.
   Finding: fixture chain releases v0.9.0 and v0.10.0 are affected;
   earlier releases lack the code path. Severity confirmed with the
   reporter before any drafting.
3. **Coordination.** The maintainer proposes a disclosure timeline to
   the reporter: fix and patch release within 14 days, coordinated
   disclosure immediately after the patch is public, reporter credited
   by name if they want attribution. The reporter agrees; the timeline
   and agreement live in the private advisory thread.
4. **Fix.** A regression test that fails on the vulnerable code is
   written first, committed with the fix. The fix itself is reviewed
   against the format specification (FORMAT.md) so the change is a
   narrowing, not a format break; the compatibility fixtures
   (box/compat_test.go) prove old files still open. Fuzz targets that
   reach the payload-copy path are extended with the hostile input as
   a seed so the class is covered from now on.
5. **Release.** The patch goes out as v0.X.1 through the normal
   three-stage pipeline (CI gate, signed draft, verify and promote).
   The release notes state plainly what the bug was, who could exploit
   it, and what users must do (upgrade; re-run `verify` on any file
   rewrapped from an untrusted source).
6. **Disclosure.** With the reporter's consent, the private advisory is
   published as a GitHub security advisory with a CVE requested
   through GitHub's CVE issuance. The changelog links the advisory, the
   fixing commit, and the regression test.
7. **Aftermath.** The advisory and the handling are recorded in the
   changelog. If the root cause suggests a gap in a test or fuzz
   target, that gap is closed in the same patch release, and this
   document gains a dated note saying the drill became real and what
   changed.

## What this tabletop commits to

- Private reporting only, through the channel SECURITY.md names.
- A same-week acknowledgment, best effort.
- Regression test before fix; fixtures prove compatibility.
- A patch release inside the normal gated pipeline, never an untested
  hotfix shortcut.
- Coordinated disclosure with the reporter's consent and credit.
- Publication of the advisory and an unredacted account of handling.

## Honest limits of the exercise

No clock was measured, no embargo was tested against a third party, and
no multi-maintainer coordination occurred, because there is one
maintainer. The first real report may invalidate any step of this
document; when that happens, the fix to the process lands with the fix
to the bug.
