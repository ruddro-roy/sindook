#!/usr/bin/env bash
# Print the docs/CHANGELOG.md section for a release version on stdout, so
# the release workflow can apply the curated notes to the promoted GitHub
# release instead of goreleaser's generated commit log.
#
# A missing section prints nothing and exits 0: release notes automation
# must never fail a release.
#
# usage: scripts/release-notes.sh X.Y.Z
#        scripts/release-notes.sh vX.Y.Z

set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 X.Y.Z" >&2
	exit 2
fi
case "$1" in
	v*) tag="$1" ;;
	*) tag="v$1" ;;
esac

changelog="$(cd "$(dirname "$0")/.." && pwd)/docs/CHANGELOG.md"
if [ ! -f "$changelog" ]; then
	echo "note: $changelog not found; no release notes applied" >&2
	exit 0
fi

# The section runs from its "## [vX.Y.Z]" heading (which may carry a date
# suffix) to the next "## [" one.
awk -v tag="$tag" '
	!found && index($0, "## [" tag "]") == 1 { found = 1; next }
	found && /^## \[/ { exit }
	found { print }
' "$changelog"
