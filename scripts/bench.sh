#!/bin/sh
# Run the Go benchmarks and print one table. The numbers in
# docs/BENCHMARKS.md are produced by this script; regenerate them with
#   scripts/bench.sh > docs/BENCHMARKS.md   (then adjust the header by
# hand: machine context and date live in prose above the table).
#
# Usage: scripts/bench.sh [benchtime]   (default 2s, Go's default)
#
# Requires: go. Benchmarks: box (seal/open/rewrap, slot cost, Argon2id)
# and cmd/sindook (verify -jobs scaling).
set -eu

benchtime=${1:-2s}
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_dir"

echo "| Benchmark | Iterations | ns/op | Throughput |"
echo "| --- | --- | ---: | ---: |"
for pkg in ./box ./cmd/sindook; do
	go test "$pkg" -run xxx -bench . -benchtime "$benchtime" 2>/dev/null |
		awk '/^Benchmark/ {
			name = $1
			iters = $2
			ns = $3
			rate = ""
			for (i = 4; i <= NF; i++)
				if ($i ~ /MB\/s|GB\/s/) rate = $(i-1) " " $i
			if (rate == "") rate = "-"
			sub(/-8$/, "", name); sub(/-[0-9]+$/, "", name)
			printf "| %s | %s | %s | %s |\n", name, iters, ns, rate
		}'
done
