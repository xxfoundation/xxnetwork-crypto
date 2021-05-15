////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package hasher

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"hash"
)

// Hasher provides easy access to various different types of hashing algorithms
type Hasher uint8

const (
	SHA2_224 Hasher = iota
	SHA2_256
	SHA2_384
	SHA2_512
	SHA3_224
	SHA3_256
	SHA3_384
	SHA3_512
	BLAKE2B_256
	BLAKE2B_384
	BLAKE2B_512
	BLAKE3_256
)

const HashersLen = BLAKE3_256 + 1 // 12

// Returns a new hasher object
func (h Hasher) New() hash.Hash {
	switch h {
	case SHA2_224:
		return sha256.New224()
	case SHA2_256:
		return sha256.New()
	case SHA2_384:
		return sha512.New384()
	case SHA2_512:
		return sha512.New()
	case SHA3_224:
		return sha3.New224()
	case SHA3_256:
		return sha3.New256()
	case SHA3_384:
		return sha3.New384()
	case SHA3_512:
		return sha3.New512()
	case BLAKE2B_256:
		b, _ := blake2b.New256(nil)
		return b
	case BLAKE2B_384:
		b, _ := blake2b.New384(nil)
		return b
	case BLAKE2B_512:
		b, _ := blake2b.New512(nil)
		return b
	case BLAKE3_256:
		return blake3.New()
	default:
		return nil
	}
}

// Returns the string representation of the hash algorithm
func (h Hasher) String() string {
	switch h {
	case SHA2_224:
		return "SHA2_224"
	case SHA2_256:
		return "SHA2_256"
	case SHA2_384:
		return "SHA2_384"
	case SHA2_512:
		return "SHA2_512"
	case SHA3_224:
		return "SHA3_224"
	case SHA3_256:
		return "SHA3_256"
	case SHA3_384:
		return "SHA3_384"
	case SHA3_512:
		return "SHA3_512"
	case BLAKE2B_256:
		return "BLAKE2B_256"
	case BLAKE2B_384:
		return "BLAKE2B_384"
	case BLAKE2B_512:
		return "BLAKE2B_512"
	case BLAKE3_256:
		return "BLAKE3_256"
	default:
		return "UNKNOWN HASH FUNCTION"
	}
}

// Returns the output size of the hash function
func (h Hasher) Size() int {
	hf := h.New()
	if hf == nil {
		return 0
	}
	return hf.Size()
}

// Returns the zero hash, i.e. Hash("")
func (h Hasher) Zero() []byte {
	hf := h.New()
	if hf == nil {
		return nil
	}
	return hf.Sum(nil)
}

// Compute hash of data, i.e. Hash(data)
func (h Hasher) Hash(data []byte) []byte {
	hf := h.New()
	if hf == nil {
		return nil
	}
	hf.Write(data)
	return hf.Sum(nil)
}
