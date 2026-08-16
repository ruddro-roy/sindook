#!/bin/bash -eu
go get github.com/AdamKorcz/go-118-fuzz-build/testing@v0.0.0-20250520111509-a70c2aa677fa
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzOpenRecipient fuzz_box_open
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzOpenPassphrase fuzz_box_open_passphrase
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzSealOpenRoundTrip fuzz_box_seal_open_round_trip
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/box FuzzBitFlip fuzz_box_bit_flip
compile_native_go_fuzzer github.com/ruddro-roy/sindook/internal/armor FuzzArmor fuzz_armor
compile_native_go_fuzzer github.com/ruddro-roy/sindook/xwing FuzzDecapsulate fuzz_xwing_decapsulate
compile_native_go_fuzzer github.com/ruddro-roy/sindook/xwing FuzzEncapsulate fuzz_xwing_encapsulate
compile_native_go_fuzzer github.com/ruddro-roy/sindook/xwing FuzzNewPrivateKey fuzz_xwing_new_private_key
compile_native_go_fuzzer github.com/ruddro-roy/sindook/xwing FuzzDecapsulateRandomIdentity fuzz_xwing_decapsulate_random_identity
