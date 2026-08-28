#!/bin/bash -eu
go get github.com/AdamKorcz/go-118-fuzz-build/testing@fc5dc53b9db8
# compile_native_go_fuzzer (legacy) silently skips a target whose name is a
# prefix of another fuzz function in the same package, because it greps
# "func Name" as a substring. The _v2 wrapper matches "func Name(" exactly
# and fails hard on ambiguity.
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzOpenRecipient fuzz_box_open
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzOpenPassphrase fuzz_box_open_passphrase
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzSealOpenRoundTrip fuzz_box_seal_open_round_trip
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzBitFlip fuzz_box_bit_flip
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzOpen fuzz_box_open_any
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzRewrap fuzz_box_rewrap
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzRewrapRoundTrip fuzz_box_rewrap_round_trip
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/box FuzzInspect fuzz_box_inspect
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/armor FuzzArmor fuzz_armor
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/armor FuzzArmorReader fuzz_armor_reader
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/armor FuzzIsArmored fuzz_is_armored
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzDecapsulate fuzz_xwing_decapsulate
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzEncapsulate fuzz_xwing_encapsulate
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzNewPrivateKey fuzz_xwing_new_private_key
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzDecapsulateRandomIdentity fuzz_xwing_decapsulate_random_identity
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/cmd/sindook FuzzLoadBaseline fuzz_cmd_load_baseline

# Guards, so a fuzz target can never go missing silently again:
# 1. every Fuzz function declared in the repository's test files must be
#    compiled by this script;
# 2. every compile line above must have produced its binary in $OUT.
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
declared=$(grep -rhoE 'func Fuzz[A-Za-z0-9_]+\([A-Za-z]+ \*testing\.F\)' --include='*_test.go' . \
    | sed -E 's/^func (Fuzz[A-Za-z0-9_]+)\(.*/\1/' | sort -u)
for fn in $declared; do
    grep -qE "^compile_native_go_fuzzer_v2 [^ ]+ $fn " "$self" \
        || { echo "ERROR: $fn is declared in a *_test.go but not compiled by $self" >&2; exit 1; }
done
for name in $(grep -oE '^compile_native_go_fuzzer_v2 [^ ]+ Fuzz[A-Za-z0-9_]+ [A-Za-z0-9_-]+' "$self" | awk '{print $4}'); do
    test -f "$OUT/$name" || { echo "ERROR: $OUT/$name was not produced" >&2; exit 1; }
done
