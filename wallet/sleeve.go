////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import (
	"encoding/base64"
	"errors"
	"github.com/tyler-smith/go-bip39"
	"gitlab.com/xx_network/crypto/hasher"
	"gitlab.com/xx_network/crypto/wots"
	"io"
	"strings"
)

var (
	wotsParams = wots.DecodeParams(wots.DefaultParams)
	path, _ = NewPath(0, uint32(wots.DefaultParams), 0)
)

const EntropySize = 32
const MnemonicWords = 24

type Sleeve struct {
	mnemonic  string
	xxAddress string
	output    string
}

///////////////////////////////////////////////////////////////////////
// CONSTRUCTORS

// Create a sleeve reading entropy from the provided CSPRNG and with the supplied passphrase
func NewSleeve(csprng io.Reader, passphrase string) (*Sleeve, error) {
	// 1. Read EntropySize bytes of entropy from csprng
	ent := make([]byte, EntropySize)
	if n, err := csprng.Read(ent); n != EntropySize || err != nil {
		return nil, errors.New("couldn't read enough bytes of entropy from provided reader")
	}

	// 2. Get sleeve from entropy
	return NewSleeveFromEntropy(ent, passphrase)
}

func NewSleeveFromEntropy(ent []byte, passphrase string) (*Sleeve, error) {
	// 1. Generate BIP39 mnemonic from entropy
	// (fails if entropy is not 16, 20, 24, 28 or 32 bytes)
	mnem, err := bip39.NewMnemonic(ent)
	if err != nil {
		return nil, err
	}

	// 2. Validate entropy has Sleeve required size of EntropySize
	if len(ent) != EntropySize {
		return nil, errors.New("provided entropy is of incorrect size")
	}

	// 3. Get Sleeve from mnemonic
	return NewSleeveFromMnemonic(mnem, passphrase)
}

func NewSleeveFromMnemonic(mnemonic, passphrase string) (*Sleeve, error) {
	// 1. Validate mnemonic has MnemonicWords words
	words := strings.Fields(mnemonic)

	if len(words) != MnemonicWords {
		return nil, errors.New("mnemonic has invalid number of words")
	}

	// 2. Generate sleeve (internally validates mnemonic)
	sl, err := generateSleeve(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}

	return sl, nil
}

///////////////////////////////////////////////////////////////////////
// GETTERS
func (s *Sleeve) GetMnemonic() string {
	return s.mnemonic
}

func (s *Sleeve) GetXXAddress() string {
	return s.xxAddress
}

func (s *Sleeve) GetOutputMnemonic() string {
	return s.output
}

///////////////////////////////////////////////////////////////////////
// PRIVATE
func generateSleeve(mnemonic, passphrase string) (*Sleeve, error) {
	// 1. Generate seed from mnemonic (validates the mnemonic)
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}

	// 2. Derive seeds using BIP32 and default path
	node, err := ComputeNode(seed, path)
	if err != nil {
		return nil, err
	}

	// 3. Generate WOTS+ key from seed and public seed
	wotsKey := wots.NewKeyFromSeed(wotsParams, node.Key, node.Code)

	// 4. Get WOTS+ Pubic Key and encode xx-address
	pk := wotsKey.ComputePK()
	xxAddress := "xx-" + base64.StdEncoding.EncodeToString(pk)

	// 5. Derive Sleeve secret key and output entropy
	secretKey := hasher.SHA3_256.Hash(append([]byte("xx network sleeve"), node.Key...))
	outEnt := hasher.SHA3_256.Hash(append(secretKey, pk...))

	// 6. Encode output entropy into BIP39 mnemonic
	outMnem, _ := bip39.NewMnemonic(outEnt)

	// 7. Create sleeve
	s := &Sleeve{
		mnemonic:  mnemonic,
		xxAddress: xxAddress,
		output:    outMnem,
	}
	return s, nil
}
