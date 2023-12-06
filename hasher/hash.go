////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package hasher

import (
	"crypto/sha256"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"hash"
)

type HashType uint8

const (
	SHA2_224 HashType = iota
	SHA2_256
	SHA3_224
	SHA3_256
	BLAKE2
	BLAKE3
)

func (h HashType) New() hash.Hash {
	switch h {
	case SHA2_224:
		return sha256.New()
	case SHA2_256:
		return sha256.New()
	case SHA3_224:
		return sha3.New224()
	case SHA3_256:
		return sha3.New256()
	case BLAKE2:
		b, _ := blake2b.New256(nil)
		return b
	case BLAKE3:
		return blake3.New()
	default:
		return nil
	}
}

func (h HashType) String() string {
	switch h {
	case SHA2_224:
		return "SHA2_224"
	case SHA2_256:
		return "SHA2_256"
	case SHA3_224:
		return "SHA3_224"
	case SHA3_256:
		return "SHA3_256"
	case BLAKE2:
		return "BLAKE2"
	case BLAKE3:
		return "BLAKE3"
	default:
		return "UNKNOWN HASH FUNCTION"
	}
}
