#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
go get github.com/AdamKorcz/go-118-fuzz-build/testing@fc5dc53b9db8
# compile_native_go_fuzzer (legacy) silently skips a target whose name is a
# prefix of another fuzz function in the same package, because it greps
# "func Name" as a substring: FuzzArmor matched FuzzArmorReader and
# FuzzDecapsulate matched FuzzDecapsulateRandomIdentity, so those two targets
# were never built. The _v2 wrapper matches "func Name(" exactly and fails
# hard on ambiguity.
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/box FuzzOpenRecipient fuzz_box_open
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/box FuzzOpenPassphrase fuzz_box_open_passphrase
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/box FuzzSealOpenRoundTrip fuzz_box_seal_open_round_trip
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/box FuzzBitFlip fuzz_box_bit_flip
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/internal/armor FuzzArmor fuzz_armor
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzDecapsulate fuzz_xwing_decapsulate
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzEncapsulate fuzz_xwing_encapsulate
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzNewPrivateKey fuzz_xwing_new_private_key
compile_native_go_fuzzer_v2 github.com/ruddro-roy/sindook/xwing FuzzDecapsulateRandomIdentity fuzz_xwing_decapsulate_random_identity
# Fail loudly if any target was silently skipped by a compiler wrapper.
for f in fuzz_box_open fuzz_box_open_passphrase fuzz_box_seal_open_round_trip \
         fuzz_box_bit_flip fuzz_armor fuzz_xwing_decapsulate \
         fuzz_xwing_encapsulate fuzz_xwing_new_private_key \
         fuzz_xwing_decapsulate_random_identity; do
  test -f "$OUT/$f" || { echo "ERROR: $OUT/$f was not produced" >&2; exit 1; }
done
