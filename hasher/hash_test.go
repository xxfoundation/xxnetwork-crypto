////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package hasher

import (
	"crypto/sha256"
	"hash"
	"reflect"
	"testing"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// Consistency test of HashType.New.
func TestHashType_New(t *testing.T) {
	newBlake2 := func() hash.Hash {
		b, _ := blake2b.New256(nil)
		return b
	}

	hashes := map[HashType]hash.Hash{
		SHA2_224: sha256.New(),
		SHA2_256: sha256.New(),
		SHA3_224: sha3.New224(),
		SHA3_256: sha3.New256(),
		BLAKE2:   newBlake2(),
		BLAKE3:   blake3.New(),
		99:       nil,
	}

	for ht, expected := range hashes {
		h := ht.New()

		if !reflect.DeepEqual(expected, h) {
			t.Errorf("Unexpected hash for type %s.\n"+
				"expected: %+v\nreceived: %+v", ht, expected, h)
		}
	}
}

// Consistency test of HashType.String.
func TestHashType_String(t *testing.T) {
	hashTypes := map[HashType]string{
		SHA2_224: "SHA2_224",
		SHA2_256: "SHA2_256",
		SHA3_224: "SHA3_224",
		SHA3_256: "SHA3_256",
		BLAKE2:   "BLAKE2",
		BLAKE3:   "BLAKE3",
		99:       "UNKNOWN HASH FUNCTION",
	}

	for ht, expected := range hashTypes {
		str := ht.String()

		if str != expected {
			t.Errorf("Unexpected string for type %d.\n"+
				"expected: %s\nreceived: %s", ht, expected, str)
		}
	}
}
