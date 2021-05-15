////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tyler-smith/go-bip39"
	"gitlab.com/xx_network/crypto/hasher"
	"gitlab.com/xx_network/crypto/wots"
	"testing"
)

type ErrReader struct {}

func (r *ErrReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("TEST")
}

type LimitedReader struct {
	limit int
}

func (r *LimitedReader) Read(p []byte) (n int, err error) {
	if r.limit > len(p) {
		r.limit -= len(p)
		return len(p), nil
	}
	return r.limit, nil
}

func TestNewSleeve(t *testing.T) {
	// Test with error reader
	_, err := NewSleeve(&ErrReader{}, "")

	if err == nil {
		t.Fatalf("NewSleeve() should return error when there's an error reading entropy")
	}

	// Test with limited bytes reader
	_, err = NewSleeve(&LimitedReader{EntropySize/2}, "")

	if err == nil {
		t.Fatalf("NewSleeve() should return error when there's an error reading enough bytes of entropy")
	}
}

func TestNewSleeveFromEntropy(t *testing.T) {
	// Test wrong entropy size (31 bytes)
	ent := make([]byte, EntropySize-1)

	_, err := NewSleeveFromEntropy(ent, "")

	if err == nil {
		t.Fatalf("NewSleeveFromEntropy() should return error when provided entropy doesn't meet BIP39 standard")
	}

	// Test valid BIP39 entropy size (16 bytes), but not enough for Sleeve
	ent = make([]byte, EntropySize/2)

	_, err = NewSleeveFromEntropy(ent, "")

	if err == nil {
		t.Fatalf("NewSleeveFromEntropy() should return error when provided entropy is of incorrect size")
	}
}

func TestNewSleeveFromMnemonic(t *testing.T) {
	// Test mnemonic with less than 24 words
	randMnem := "one two three xx    network   sleeve implementation"

	_, err := NewSleeveFromMnemonic(randMnem, "")

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has invalid number of words")
	}

	// Test mnemonic with 24 words but one invalid word
	invalidWordMnem := "armed output survey rent myself sentence warm eyebrow scan isolate thunder point" +
		" bulk skirt sketch bird palm sleep dash jazz list behave spin xxnetwork"

	_, err = NewSleeveFromMnemonic(invalidWordMnem, "")

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has an invalid work")
	}

	// Test mnemonic with 24 words but invalid checksum
	invalidChkMnem := "armed output survey rent myself sentence warm eyebrow scan isolate thunder point" +
		" bulk skirt sketch bird palm sleep dash jazz list behave spin spin"

	_, err = NewSleeveFromMnemonic(invalidChkMnem, "")

	if err == nil {
		t.Fatalf("NewSleeveFromMnemonic() should return error when provided mnemonic has incorrect checksum")
	}
}

// Test vector taken from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
const (
	testVectorEntropy = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"
	testVectorMnemonic = "hamster diagram private dutch cause delay private meat slide toddler razor book" +
		" happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
	testVectorSeed = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"
)

func TestSleeve_Getters(t *testing.T) {
	// Test valid Sleeve and getters
	sleeve, err := NewSleeve(rand.Reader, "")

	if err != nil {
		t.Fatalf("NewSleeve() shouldn't return error in valid generation")
	}

	if sleeve.GetMnemonic() == "" {
		t.Fatalf("GetMnemonic() returned empty string after Sleeve generation")
	}

	if sleeve.GetXXAddress() == "" {
		t.Fatalf("GetXXAddress() returned empty string after Sleeve generation")
	}

	if sleeve.GetOutputMnemonic() == "" {
		t.Fatalf("GetOutputMnemonic() returned empty string after Sleeve generation")
	}
}

func TestSleeve_Consistency(t *testing.T) {
	// Test Sleeve with provided test vector
	ent, _ := hex.DecodeString(testVectorEntropy)
	sleeve, err := NewSleeveFromEntropy(ent, "TREZOR")

	if err != nil {
		t.Fatalf("NewSleeveFromEntropy() shouldn't return error in valid generation")
	}

	// Validate mnemonic is correct
	if sleeve.GetMnemonic() != testVectorMnemonic {
		t.Fatalf("Consistency violation! GetMnemonic() returned wrong mnemonic. Got %s, expected %s",
			sleeve.GetMnemonic(), testVectorMnemonic)
	}

	// Manually derive Sleeve from test seed and prove consistency
	seed, _ := hex.DecodeString(testVectorSeed)
	// Path = m/44'/1955'/0'/0'/0'
	n, _ := ComputeNode(seed, []uint32{0x8000002C, 0x800007A3, 0x80000000, 0x80000000, 0x80000000})
	wotsKey := wots.NewKeyFromSeed(wots.DecodeParams(wots.DefaultParams), n.Key, n.Code)
	pk := wotsKey.ComputePK()
	xxAddr := "xx-" + base64.StdEncoding.EncodeToString(pk)

	// Compare WOTS+ address
	if sleeve.GetXXAddress() != xxAddr {
		t.Fatalf("Consistency violation! GetXXAddress() returned wrong xx address. Got %s, expected %s",
			sleeve.GetXXAddress(), xxAddr)
	}

	key := hasher.SHA3_256.Hash(append([]byte("xx network sleeve"), n.Key...))
	outEnt := hasher.SHA3_256.Hash(append(key, pk...))
	outMnem, _ := bip39.NewMnemonic(outEnt)

	// Compare output mnemonic
	if sleeve.GetOutputMnemonic() != outMnem {
		t.Fatalf("Consistency violation! GetOutputMnemonic() returned wrong output mnemonic." +
			" Got %s, expected %s", sleeve.GetOutputMnemonic(), outMnem)
	}
}
