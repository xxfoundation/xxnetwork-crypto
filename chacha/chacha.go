////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package chacha contains logic for encryption and decryption using
// the chacha20poly1305 encryption algorithm.
package chacha

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts plaintext data using using chacha20poly1305.
// This encryption algorithm is initialized by passing in the
// encryption key, which must be 256 bits.
func Encrypt(key, data []byte, rng csprng.Source) (ciphertext []byte, error error) {
	chaCipher, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, errors.Errorf("Failed to initalize encryption algorithm: %v", err)
	}

	// Generate the nonce
	nonce := make([]byte, chaCipher.NonceSize())
	nonce, err = csprng.Generate(chaCipher.NonceSize(), rng)
	if err != nil {
		return nil, errors.Errorf("Failed to generate nonce: %v", err)
	}

	ciphertext = chaCipher.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext data using using chacha20poly1305.
// This encryption algorithm is initialized by passing in the
// encryption key, which must be 256 bits.
func Decrypt(key, data []byte) (plaintext []byte, err error) {
	chaCipher, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, errors.Errorf("Failed to initalize encryption algorithm: %v", err)
	}

	nonceLen := chaCipher.NonceSize()
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err = chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot decrypt with password!")
	}
	return plaintext, nil
}
