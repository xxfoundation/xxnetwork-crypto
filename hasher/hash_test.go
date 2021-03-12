////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package hasher

import "testing"

func testNew(typ HashType, t *testing.T) {
	h := typ.New()

	if h == nil {
		t.Errorf("HashType.New() returned nil hash function for a valid type!")
	}
}

func TestHashType_New(t *testing.T) {
	testNew(SHA2_224, t)
	testNew(SHA2_256, t)
	testNew(SHA3_224, t)
	testNew(SHA3_256, t)
	testNew(BLAKE2, t)
	testNew(BLAKE3, t)

	// Test non existing type
	typ := HashType(20)
	h := typ.New()

	if h != nil {
		t.Errorf("HashType.New() should have returned nil hash function for unknown type!")
	}
}

func testString(typ HashType, t *testing.T) {
	str := typ.String()

	if str == "UNKNOWN HASH FUNCTION" {
		t.Errorf("HashType.String() returned unexpected string for a valid type!")
	}
}

func TestHashType_String(t *testing.T) {
	testString(SHA2_224, t)
	testString(SHA2_256, t)
	testString(SHA3_224, t)
	testString(SHA3_256, t)
	testString(BLAKE2, t)
	testString(BLAKE3, t)

	// Test non existing type
	typ := HashType(20)
	str := typ.String()

	if str != "UNKNOWN HASH FUNCTION" {
		t.Errorf("HashType.String() should have returned unknown hash function string for an unknown type!")
	}
}
