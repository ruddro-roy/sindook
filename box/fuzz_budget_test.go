package box

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fuzzBudgetV1Pass(ticks, memory uint32, threads uint8) []byte {
	b := []byte(magicV1)
	b = append(b, modeV1Passphrase)
	var params [9]byte
	binary.BigEndian.PutUint32(params[0:4], ticks)
	binary.BigEndian.PutUint32(params[4:8], memory)
	params[8] = threads
	b = append(b, params[:]...)
	b = append(b, make([]byte, saltSize+fileNonceSize)...)
	return b
}

func fuzzBudgetV2(slots ...struct {
	typ  byte
	body []byte
}) []byte {
	b := []byte(magicV2)
	b = append(b, make([]byte, fileNonceSize)...)
	b = append(b, byte(len(slots)))
	for _, s := range slots {
		var head [3]byte
		head[0] = s.typ
		binary.BigEndian.PutUint16(head[1:3], uint16(len(s.body)))
		b = append(b, head[:]...)
		b = append(b, s.body...)
	}
	b = append(b, make([]byte, macSize)...)
	return b
}

func fuzzBudgetPassSlot(ticks, memory uint32, threads uint8) []byte {
	body := make([]byte, passSlotBody)
	binary.BigEndian.PutUint32(body[0:4], ticks)
	binary.BigEndian.PutUint32(body[4:8], memory)
	body[8] = threads
	return body
}

func TestArgonWorkBoundedMirrorsParserCost(t *testing.T) {
	defaultWorkSlot := fuzzBudgetPassSlot(DefaultArgon2id.Time, DefaultArgon2id.MemoryKiB, DefaultArgon2id.Threads)
	heavySlot := fuzzBudgetPassSlot(maxArgonTime, maxArgonMemoryKiB, 1)
	invalidHeavySlot := fuzzBudgetPassSlot(0, maxArgonMemoryKiB, 1)
	shortHeavyBody := heavySlot[:8]

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "v1 default parameters fit the fuzz budget",
			data: fuzzBudgetV1Pass(DefaultArgon2id.Time, DefaultArgon2id.MemoryKiB, DefaultArgon2id.Threads),
			want: true,
		},
		{
			name: "v1 parser-accepted maximum parameters exceed the fuzz budget",
			data: fuzzBudgetV1Pass(maxArgonTime, maxArgonMemoryKiB, 1),
			want: false,
		},
		{
			name: "invalid v1 parameters are rejected before kdf work",
			data: fuzzBudgetV1Pass(0, maxArgonMemoryKiB, 1),
			want: true,
		},
		{
			name: "one v2 default passphrase slot fits the fuzz budget",
			data: fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotPassphrase, defaultWorkSlot}),
			want: true,
		},
		{
			name: "two v2 default passphrase slots are summed",
			data: fuzzBudgetV2(
				struct {
					typ  byte
					body []byte
				}{SlotPassphrase, defaultWorkSlot},
				struct {
					typ  byte
					body []byte
				}{SlotPassphrase, defaultWorkSlot},
			),
			want: false,
		},
		{
			name: "valid heavy v2 passphrase slot exceeds the fuzz budget",
			data: fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotPassphrase, heavySlot}),
			want: false,
		},
		{
			name: "invalid v2 parameters are rejected before kdf work",
			data: fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotPassphrase, invalidHeavySlot}),
			want: true,
		},
		{
			name: "wrong-sized v2 passphrase body is rejected before kdf work",
			data: fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotPassphrase, shortHeavyBody}),
			want: true,
		},
		{
			name: "truncated v2 header is rejected before kdf work",
			data: bytes.TrimSuffix(fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotPassphrase, heavySlot}), make([]byte, macSize)),
			want: true,
		},
		{
			name: "recipient-only v2 header has no passphrase kdf work",
			data: fuzzBudgetV2(struct {
				typ  byte
				body []byte
			}{SlotXWing, make([]byte, xwingSlotBody)}),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := argonWorkBounded(tt.data); got != tt.want {
				t.Fatalf("argonWorkBounded() = %v, want %v", got, tt.want)
			}
		})
	}
}
