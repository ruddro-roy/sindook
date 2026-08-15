package box

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ruddro-roy/sindook/xwing"
)

// selfTestArgon keeps the runtime self-test fast while still satisfying
// Argon2idParams.validate.
var selfTestArgon = Argon2idParams{Time: 1, MemoryKiB: 8, Threads: 1}

// SelfTest exercises the box format end to end without any testdata: a
// round trip through a recipient slot and a passphrase slot, rejection of
// wrong credentials, and detection of tampered or truncated sealed files.
func SelfTest() error {
	k, err := xwing.GenerateKey()
	if err != nil {
		return fmt.Errorf("sindook: self-test: cannot generate x-wing key: %w", err)
	}

	// Deterministic 100 KiB pattern, no math/rand dependency: repeating
	// counter bytes.
	plain := make([]byte, 100*1024)
	for i := range plain {
		plain[i] = byte(i)
	}
	pass := []byte("correct horse battery staple")
	opts := SealOptions{
		Recipients:  [][]byte{k.PublicKey()},
		Passphrases: [][]byte{pass},
		Argon:       selfTestArgon,
	}
	var sealed bytes.Buffer
	if err := Seal(&sealed, bytes.NewReader(plain), opts); err != nil {
		return fmt.Errorf("sindook: self-test: seal: %w", err)
	}
	blob := sealed.Bytes()

	var out bytes.Buffer
	if err := Open(&out, bytes.NewReader(blob), k, nil); err != nil {
		return fmt.Errorf("sindook: self-test: open with identity: %w", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		return errors.New("sindook: self-test: round trip plaintext mismatch (identity slot)")
	}
	out.Reset()
	if err := Open(&out, bytes.NewReader(blob), nil, pass); err != nil {
		return fmt.Errorf("sindook: self-test: open with passphrase: %w", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		return errors.New("sindook: self-test: round trip plaintext mismatch (passphrase slot)")
	}

	stranger, err := xwing.GenerateKey()
	if err != nil {
		return fmt.Errorf("sindook: self-test: cannot generate second key: %w", err)
	}
	if err := Open(io.Discard, bytes.NewReader(blob), stranger, nil); err == nil {
		return errors.New("sindook: self-test: wrong identity accepted")
	}
	if err := Open(io.Discard, bytes.NewReader(blob), nil, []byte("wrong passphrase")); err == nil {
		return errors.New("sindook: self-test: wrong passphrase accepted")
	}
	if err := Open(io.Discard, bytes.NewReader(blob[:len(blob)-1]), k, nil); err == nil {
		return errors.New("sindook: self-test: truncated file accepted")
	}
	tampered := append([]byte(nil), blob...)
	tampered[8] ^= 0x01
	if err := Open(io.Discard, bytes.NewReader(tampered), k, nil); err == nil {
		return errors.New("sindook: self-test: tampered header accepted")
	}
	var empty bytes.Buffer
	if err := Seal(&empty, bytes.NewReader(plain[:1]), SealOptions{}); err == nil {
		return errors.New("sindook: self-test: seal with zero recipients succeeded")
	}
	return nil
}
