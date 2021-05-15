////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package hasher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testNew(typ Hasher, t *testing.T) {
	h := typ.New()

	if h == nil {
		t.Errorf("Hasher.New() returned nil hash function for a valid type!")
	}
}

func TestHashType_New(t *testing.T) {
	// Test all existing types
	for i := Hasher(0); i < HashersLen; i++ {
		testNew(i, t)
	}

	// Test non existing type
	typ := HashersLen
	h := typ.New()

	if h != nil {
		t.Errorf("Hasher.New() should have returned nil hash function for unknown type!")
	}
}

func testString(typ Hasher, t *testing.T) {
	str := typ.String()

	if str == "UNKNOWN HASH FUNCTION" {
		t.Errorf("Hasher.String() returned unexpected string for a valid type!")
	}
}

func TestHashType_String(t *testing.T) {
	// Test all existing types
	for i := Hasher(0); i < HashersLen; i++ {
		testString(i, t)
	}

	// Test non existing type
	typ := HashersLen
	str := typ.String()

	if str != "UNKNOWN HASH FUNCTION" {
		t.Errorf("Hasher.String() should have returned unknown hash function string for an unknown type!")
	}
}

var sizes = [HashersLen]int {28, 32, 48, 64, 28, 32, 48, 64, 32, 48, 64, 32}

func testSize(typ Hasher, t *testing.T) {
	size := typ.Size()

	if size != sizes[typ] {
		t.Errorf("Hasher.Size() returned wrong size! Got %d, expected %d", size, sizes[typ])
	}
}

func TestHashType_Size(t *testing.T) {
	// Test all existing types
	for i := Hasher(0); i < HashersLen; i++ {
		testSize(i, t)
	}

	// Test non existing type
	typ := HashersLen
	size := typ.Size()

	if size != 0 {
		t.Errorf("Hasher.Size() should have returned 0 unknown type! Got %d instead", size)
	}
}

// ----------------------------------------------------------------------------------------------------------------- //
// TEST VECTORS FOR ZERO HASHES
// SHA2 and SHA3 zero hashes taken from https://www.di-mgt.com.au/sha_testvectors.html
// BLAKE2 zero hashes taken from official test vectors https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
// BLAKE3 zero hashes taken from official b3sum utility https://github.com/BLAKE3-team/BLAKE3 reading /dev/null
var zeroHashes = [HashersLen]string {
	"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",                                          // SHA2_224
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",                                  // SHA2_256
	"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",  // SHA2_384
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f" +
		"63b931bd47417a81a538327af927da3e",                                                              // SHA2_512

	"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",                                          // SHA3_224
	"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",                                  // SHA3_256
	"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",  // SHA3_384
	"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558" +
		"f500199d95b6d3e301758586281dcd26",                                                              // SHA3_512

	"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",                                  // BLAKE2B_256
	"b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",  // BLAKE2B_384
	"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b" +
		"903a685b1448b755d56f701afe9be2ce",                                                              // BLAKE2B_512

	"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",                                  // BLAKE3_256
}
// ----------------------------------------------------------------------------------------------------------------- //

func testZero(typ Hasher, t *testing.T) {
	zero := typ.Zero()
	str := typ.String()

	ref, _ := hex.DecodeString(zeroHashes[typ])

	if !bytes.Equal(zero, ref) {
		t.Errorf("%s: Hasher.Zero() returned wrong zero hash! Got %x, expected %x", str, zero, ref)
	}
}

func TestHashType_Zero(t *testing.T) {
	// Test all existing types
	for i := Hasher(0); i < HashersLen; i++ {
		testZero(i, t)
	}

	// Test non existing type
	typ := HashersLen
	zero := typ.Zero()

	if zero != nil {
		t.Errorf("Hasher.Zero() should have returned nil! Got %x instead", zero)
	}
}

// ----------------------------------------------------------------------------------------------------------------- //
// TEST VECTORS FOR HASH OF "XX NETWORK"
var testData = []byte("XX NETWORK")
var xxnetworkHashes = [HashersLen]string {
	"6a905b985890a431c9b0325c6b9550332248fcd3e3e65f29e06db9dc",                                          // SHA2_224
	"34fc112ddd8ae48abcfd01224b09d98d6cfeb54ad9261595efd80403bb610971",                                  // SHA2_256
	"a33c0ed9aba5539ce7896c9936d3ab0859b2a117092fde813b13fb6e7b290de31c0fb848eea4e36ca7d5179d89623a8f",  // SHA2_384
	"d456de5ab38a8060141577dd839e0f5885df1165dc51677914d904b62e87ec02f3e91de356acca96b82bad35ed6f51e7" +
		"76aeb82a960d972c65e8e22ccb59c86a",                                                              // SHA2_512

	"520804086c653ae6c0bb9feafc267db8613cb333e092afedcf006df5",                                          // SHA3_224
	"267ff9cedc70abe2bf323fdc4803bdd1fbb6005662712bae075f7391d8804001",                                  // SHA3_256
	"d414c016caf880522a63fe9a35071fc1ee45fc862aa24911415d97738b2fcaf031f12630f1697c2593e9b21865bcd94b",  // SHA3_384
	"c5304df0194881a71c9896c4e5bf5505055b8a4f91bc7fd7b2e9fa9d46700947a062283ec4d3e579e9879fbba6e5e7b4" +
		"52e8c04a94220b5c9559dcea1a4c8cb3",                                                              // SHA3_512

	"2bc7a74e5f06ff5afa3d494dff5e48fc481d34dacc9610b0f385ddce93452c0f",                                  // BLAKE2B_256
	"65cac639489205cd7973a90dc5c2ec88d495d54607b972808646dfaf4f5750699d3303b6c3d044800562c2bf66a7f2db",  // BLAKE2B_384
	"3d4e7d11fac86f7b5f697fde7da4998e74a067f50aa080c9f3dd584bbe80db292ec6df9bb61fc18e130a3e52fb8d361b" +
		"ae8728703d4fc20df69426a2518c1a4d",                                                              // BLAKE2B_512

	"65bf8ea0fba6d6a5e4b34593ae374914370ad0d271ba23313bfcd973fb341c21",                                  // BLAKE3_256
}
// ----------------------------------------------------------------------------------------------------------------- //

func testHash(typ Hasher, t *testing.T) {
	hash := typ.Hash(testData)
	str := typ.String()

	ref, _ := hex.DecodeString(xxnetworkHashes[typ])

	if !bytes.Equal(hash, ref) {
		t.Errorf("%s: Hasher.Hash() returned wrong hash! Got %x, expected %x", str, hash, ref)
	}
}

func TestHashType_Hash(t *testing.T) {
	// Test all existing types
	for i := Hasher(0); i < HashersLen; i++ {
		testHash(i, t)
	}

	// Test non existing type
	typ := HashersLen
	hash := typ.Hash(testData)

	if hash != nil {
		t.Errorf("Hasher.Hash() should have returned nil! Got %x instead", hash)
	}
}