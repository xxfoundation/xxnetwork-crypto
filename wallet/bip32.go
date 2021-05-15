////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"gitlab.com/xx_network/crypto/hasher"
	"math/big"
)

const (
	keySize       = 32
	minSeedSize   = 16
	maxSeedSize   = 64
	firstHardened = uint32(0x80000000)
)

// N corresponds to the order of the base point G from the secp256k1. Here written in hex.
const hexN = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
var N *big.Int

func init() {
	aux, _ := hex.DecodeString(hexN)
	N = new(big.Int).SetBytes(aux)
}

type Node struct {
	Key  []byte
	Code []byte
}

// Derive the master node from a seed
func NewMasterNode(seed []byte) (*Node, error) {
	// Check if seed has valid size
	if len(seed) < minSeedSize || len(seed) > maxSeedSize {
		return nil, errors.New("NewMasterNode: invalid seed size")
	}

	// Generate HMAC-SHA512 with hardcoded seed as Key
	h := hmac.New(hasher.SHA2_512.New, []byte("Bitcoin seed"))

	// Data: H(seed)
	h.Write(seed)
	aux := h.Sum(nil)

	// Validate Private Key
	err := validatePrivateKey(aux[:keySize])
	if err != nil {
		return nil, err
	}

	// Export Key and Chain Code from aux
	node := &Node{
		Key:  aux[:keySize],
		Code: aux[keySize:],
	}
	return node, nil
}

// Compute the hardened child node with given index
// Place child Key and Code directly in Node (mutate)
// Only hard derivations allowed, so idx must be >= 2^31
func (n *Node) ComputeHardenedChild(idx uint32) error {
	// check index corresponds to a hardened child
	if idx < firstHardened {
		return errors.New("child index must be >= 2^31")
	}

	// convert idx to bytes
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, idx)

	// Generate HMAC-SHA512 with Chain Code as Key
	h := hmac.New(hasher.SHA2_512.New, n.Code)

	// Data: H(0x00 || key || byte(idx))
	h.Write([]byte{0x00}) // used since it's hardened derivation
	h.Write(n.Key)
	h.Write(idxBytes)
	aux := h.Sum(nil)

	// aux[:32] + key (mod N)
	keyInt := big.NewInt(0).SetBytes(n.Key)
	auxInt := big.NewInt(0).SetBytes(aux[:keySize])
	keyInt.Add(auxInt, keyInt)
	keyInt.Mod(keyInt, N)

	// validate Private key
	err := validateKeyNotZero(keyInt)
	if err != nil {
		return err
	}

	// convert to 32-byte slice
	b := keyInt.Bytes()
	if len(b) < keySize {
		extra := make([]byte, keySize-len(b))
		b = append(extra, b...)
	}

	// Place child Key and Code directly in Node (mutate)
	copy(n.Key, b)
	copy(n.Code, aux[keySize:])

	return nil
}

// Validate Private Key
func validatePrivateKey(keyBytes []byte) error {
	key := big.NewInt(0).SetBytes(keyBytes)
	err := validateKeyNotZero(key)
	if err != nil {
		return err
	}

	if key.Cmp(N) >= 0 {
		return errors.New("validatePrivateKey: key bigger or equal than N")
	}
	return nil
}

// Check if Key is 0
func validateKeyNotZero(key *big.Int) error {
	// Check if key = 0
	if len(key.Bits()) == 0 {
		return errors.New("validateKeyNotZero: key is 0")
	}
	return nil
}
