////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package chacha

import (
	"bytes"
	"errors"
	"fmt"
	"gitlab.com/xx_network/crypto/csprng"
	"io"
	"math/rand"
	"strings"
	"testing"
)

var expectedSig = []byte{223, 215, 155, 77, 118, 66, 155, 97, 122, 12, 159,
	159, 13, 59, 165, 91, 12, 192, 214, 20, 76, 136, 133, 53, 71, 143, 14,
	203, 115, 63, 85, 20, 255, 105, 22, 216, 99, 53, 9, 79, 209, 159, 29,
	85, 104, 158, 120, 188, 209, 84, 29, 252, 133, 9, 164, 185, 176, 50, 88,
	42, 98, 196, 127}

// Tests consistency of encryption. If this test fails, it's likely a
// smoke signal that underlying dependencies have been changed.
func TestEncrypt_Consistency(t *testing.T) {
	notRand := NewPrng(42)

	key := make([]byte, 32)
	_, err := notRand.Read(key)
	if err != nil {
		t.Fatalf("Could not generate mock key: %v", err)
	}

	data := []byte("Secret data do not read")
	// Encrypt the secret
	ciphertext, err := Encrypt(key, data, notRand)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if !bytes.Equal(ciphertext, expectedSig) {
		t.Fatalf("Unexpected ciphertext received. "+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expectedSig, ciphertext)
	}
}

// Error case: pass in a key with a bad length
func TestEncrypt_NilKey(t *testing.T) {
	notRand := NewPrng(42)

	data := []byte("Secret data do not read")
	// Encrypt the secret
	_, err := Encrypt(nil, data, notRand)
	if err == nil || !strings.Contains(err.Error(), "bad key length") {
		t.Fatalf("Encrypt should have errored with a bad key length")
	}
}

// Error case: force a nonce generation error.
func TestEncrypt_BadRng(t *testing.T) {
	badRand := NewBadPrng(42)
	notRand := NewPrng(42)

	key := make([]byte, 32)
	_, err := notRand.Read(key)
	if err != nil {
		t.Fatalf("Could not generate mock key: %v", err)
	}

	data := []byte("Secret data do not read")
	// Encrypt the secret
	_, err = Encrypt(key, data, &badRand)
	if err == nil || !strings.Contains(err.Error(), "Failed to generate nonce") {
		t.Fatalf("Encrypt should have errored with due to failure to generate a nonce")
	}
}

// Tests that encrypt and decrypt are inverse operations, ie. ensures
// encrypted data passed into decrypt returns the original plaintext.
func TestEncryptDecryptMnemonic(t *testing.T) {
	notRand := NewPrng(42)

	key := make([]byte, 32)
	_, err := notRand.Read(key)
	if err != nil {
		t.Fatalf("Could not generate mock key: %v", err)
	}

	data := []byte("Secret data do not read")
	// Encrypt the secret
	ciphertext, err := Encrypt(key, data, notRand)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Decrypt the secret
	received, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	// Test if secret matches decrypted data
	if !bytes.Equal(received, data) {
		t.Fatalf("Decrypted data does not match original plaintext."+
			"\n\tExpected: %v\n\tReceived: %v", data, received)
	}
}

// Prng is a PRNG that satisfies the csprng.Source interface.
type Prng struct{ prng io.Reader }

func NewPrng(seed int64) csprng.Source     { return &Prng{rand.New(rand.NewSource(seed))} }
func (s *Prng) Read(b []byte) (int, error) { return s.prng.Read(b) }
func (s *Prng) SetSeed([]byte) error       { return nil }

// BadPrng is a PRNG that satisfies the csprng.Source interface.
type BadPrng struct{}

func NewBadPrng(seed int64) BadPrng { return BadPrng{} }
func (s *BadPrng) Read(b []byte) (int, error) {
	fmt.Printf("doo doo\n")
	return 0, errors.New("error path")
}
func (s *BadPrng) SetSeed([]byte) error { return nil }
