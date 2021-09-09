////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package mnemonic provides english mnemonic encodings wrapping the golang
// bip32 reference implementation.
package mnemonic

import (
	"errors"
	bip39 "github.com/tyler-smith/go-bip39"
	"gitlab.com/xx_network/crypto/csprng"
)

// GenerateMnemonic uses a CSPRNG to geenerate a seed then returns the
// corresponding english mnemonic. numBytes must be divisble by 4 and between
// 16 and 32.
func GenerateMnemonic(rng csprng.Source, numBytes int) (string, error) {
	if (numBytes%4) != 0 || numBytes < 16 || numBytes > 32 {
		return "", bip39.ErrEntropyLengthInvalid
	}

	seed := make([]byte, numBytes)
	bytesGenerated, err := rng.Read(seed)
	if err != nil {
		return "", err
	}
	if bytesGenerated != numBytes {
		return "", errors.New("Could not fully read entropy source")
	}
	return EncodeMnemonic(seed)
}

// EncodeMnemonic encodes a given seed into a BIP39 english mnemonic.
// Note that if you are using a password you should run this through pkbdf or
// similar, do not send the password to this directly.
func EncodeMnemonic(seed []byte) (string, error) {
	return bip39.NewMnemonic(seed)
}

// DecodeMnemonic decodes a given mnemonic into a seed (the original entropy)
func DecodeMnemonic(mnemonic string) ([]byte, error) {
	return bip39.EntropyFromMnemonic(mnemonic)
}
