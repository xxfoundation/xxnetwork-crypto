////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"gitlab.com/xx_network/crypto/hasher"
	"reflect"
	"testing"
)

type ErrReader struct {
	read int
}

func (r *ErrReader) Read(p []byte) (n int, err error) {
	if r.read == 0 {
		return 0, errors.New("TEST")
	}
	r.read--
	return len(p), nil
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

func TestNewKey(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	// Test NewKey works with real reader
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test with error reader on first read
	key = NewKey(params, &ErrReader{0})

	if key != nil {
		t.Fatalf("NewKey should return nil when there's an error reading seed!")
	}

	// Test with error reader on second read
	key = NewKey(params, &ErrReader{1})

	if key != nil {
		t.Fatalf("NewKey should return nil when there's an error reading public seed!")
	}

	// Test with limited bytes reader, with not enough bytes for secret seed
	key = NewKey(params, &LimitedReader{24})

	if key != nil {
		t.Fatalf("NewKey should return nil when can't read enough bytes for secret seed!")
	}

	// Test with limited bytes reader, with not enough bytes for public seed
	key = NewKey(params, &LimitedReader{60})

	if key != nil {
		t.Fatalf("NewKey should return nil when can't read enough bytes for public seed!")
	}
}

func TestNewKeyFromSeed(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	// Test NewKeyFromSeed returns nil when seeds have wrong size
	seed := make([]byte, 30)
	n, err := rand.Read(seed)

	if err != nil {
		t.Fatalf("Error reading random bytes for seed: %s", err)
	}

	if n != 30 {
		t.Fatalf("Reader only gave us %d bytes, expected 30", n)
	}

	pSeed := make([]byte, 32)
	n, err = rand.Read(pSeed)

	if err != nil {
		t.Fatalf("Error reading random bytes for public seed: %s", err)
	}

	if n != 32 {
		t.Fatalf("Reader only gave us %d bytes, expected 32", n)
	}

	key := NewKeyFromSeed(params, seed, pSeed)

	if key != nil {
		t.Fatalf("NewKeyFromSeed should return nil when secret seed is too small!")
	}

	key = NewKeyFromSeed(params, pSeed, seed)

	if key != nil {
		t.Fatalf("NewKeyFromSeed should return nil when public seed is too small!")
	}

	// Test NewKeyFromSeed works when seeds are correct
	key = NewKeyFromSeed(params, pSeed, pSeed)

	if key == nil {
		t.Fatalf("NewKeyFromSeed returned nil")
	}
}

func TestKey_GetPK(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test get public key is empty
	pk := key.GetPK()

	if pk != nil {
		t.Fatalf("Key.GetPK should return nil when key is not generated!")
	}

	// Replace PK and test get public key again
	expected := make([]byte, PKSize)
	copy(expected, "PUBLIC_KEY_1234567890")
	key.pk = expected

	public := key.GetPK()

	if !reflect.DeepEqual(public, expected) {
		t.Fatalf("Key.GetPK didn't return correct public key!")
	}
}

func TestKey_ComputePK(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test compute PK
	pk := key.ComputePK()

	if pk == nil {
		t.Fatalf("Key.ComputePK didn't generate public key!")
	}

	if len(pk) != PKSize {
		t.Fatalf("Key.ComputePK didn't generate public key of correct size!")
	}

	// Test computePK doesn't run twice
	// Override public seed to prove that PK remained the same
	key.seed = make([]byte, 32)
	copy(key.seed, "SECRET_SEED_1234567890")

	pk2 := key.ComputePK()

	if !reflect.DeepEqual(pk, pk2) {
		t.Fatalf("Key.ComputePK modified PK on second call!")
	}
}

func TestKey_Generate(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test generate
	key.Generate()

	pk := key.GetPK()

	if pk == nil {
		t.Fatalf("Key.Generate didn't generate public key!")
	}

	if len(pk) != PKSize {
		t.Fatalf("Key.Generate didn't generate public key of correct size!")
	}

	// Test generate doesn't run twice
	// Override public seed to prove that PK remained the same
	key.seed = make([]byte, 32)
	copy(key.seed, "SECRET_SEED_1234567890")

	key.Generate()

	pk2 := key.GetPK()

	if !reflect.DeepEqual(pk, pk2) {
		t.Fatalf("Key.Generate modified PK on second call!")
	}
}

func TestKey_Sign(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test Signing without generating does not keep data in memory
	msg := make([]byte, 256)
	n, err := rand.Read(msg)

	if err != nil {
		t.Fatalf("Error reading random bytes for msg: %s", err)
	}

	if n != 256 {
		t.Fatalf("Reader only gave us %d bytes, expected 256", n)
	}

	sig := key.Sign(msg)

	if sig == nil {
		t.Fatalf("Key.Sign returned nil signature!")
	}

	// Signature size: ParamsEncoding (1 byte), Public Seed (32 bytes), Ladders (M+2)*N bytes
	sigLen := 1 + 32 + (32 + 2) * 32

	if len(sig) != sigLen {
		t.Fatalf("Key.Sign returned signature is too small! Expected %d, Got %d",
			sigLen, len(sig))
	}

	// Test Signing after generation returns same signature
	key.Generate()

	sig2 := key.Sign(msg)

	if sig2 == nil {
		t.Fatalf("Key.Sign returned nil signature!")
	}

	if len(sig2) != sigLen {
		t.Fatalf("Key.Sign returned signature is too small! Expected %d, Got %d",
			sigLen, len(sig2))
	}

	if !bytes.Equal(sig, sig2) {
		t.Fatalf("Key.Sign does not return the same signature before and after Generate()!")
	}

}

func TestKey_Sign_Consistency(t *testing.T) {
	params := NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256)
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test signing + decoding
	msg := make([]byte, 256)
	n, err := rand.Read(msg)

	if err != nil {
		t.Fatalf("Error reading random bytes for msg: %s", err)
	}

	if n != 256 {
		t.Fatalf("Reader only gave us %d bytes, expected 256", n)
	}

	key.Generate()

	sig := key.Sign(msg)
	pk := key.GetPK()

	ret := make([]byte, 0, PKSize)
	ret = params.Decode(ret, msg, sig[1:])

	if !bytes.Equal(ret, pk) {
		t.Fatalf("Key.Sign + Params.Decode are not consistent! Expected PK: %v, Got: %v",
			pk, ret)
	}
}

/////////////////////////////////////////////////
///////////////// TEST VECTORS //////////////////
/////////////////////////////////////////////////
const (
	// 255*32 = 8160
	MaxChecksum256 = "1fe0"
	// 255*28 = 7140
	MaxChecksum224 = "1be4"
	// 255*24 = 6120
	MaxChecksum192 = "17e8"
	MinChecksum = "0000"
)

const TestData = "XX NETWORK"

/////////////////////////////////////////////////
// Indexes computed as follows:
// 1. H = SHA3_256("XX NETWORK")
// 2. CHECK = CHECKSUM(H)
// 3. TestVector256 = CONVERT_TO_UINT8s(H || CHECK)
// Where CONVERT_TO_UINT8s, takes each byte of the sequence H || CHECK and converts it to an uint8
var TestVector256 = []uint8{
	 38, 127, 249, 206, 220, 112, 171, 226,
	191,  50,  63, 220,  72,   3, 189, 209,
	251, 182,   0,  86,  98, 113,  43, 174,
	  7,  95, 115, 145, 216, 128,  64,   1,
    // Checksum
	 16,   0,
}

// 255*32 - SUM(TestVector256[0:31]) = 255*32 - 4064 = 4096
const Checksum256 = "1000"

/////////////////////////////////////////////////
// Indexes computed as follows:
// 1. H = SHA3_224("XX NETWORK")
// 2. CHECK = CHECKSUM(H)
// 3. TestVector224 = CONVERT_TO_UINT8s(H || CHECK)
var TestVector224 = []uint8{
	 82,   8,   4,   8, 108, 101,  58, 230,
	192, 187, 159, 234, 252,  38, 125, 184,
	 97,  60, 179,  51, 224, 146, 175, 237,
	207,   0, 109, 245,
	// Checksum
	 13, 112,
}

// 255*28 - SUM(TestVector224[0:27]) = 255*28 - 3700 = 3440
const Checksum224 = "0d70"

/////////////////////////////////////////////////
// Indexes computed as follows:
// 1. H = SHA3_224("XX NETWORK")
// 2. CHECK = CHECKSUM(H[0:23])
// 3. TestVector192 = CONVERT_TO_UINT8s(H[0:23] || CHECK)
var TestVector192 = []uint8{
	82,   8,   4,   8, 108, 101,  58, 230,
	192, 187, 159, 234, 252,  38, 125, 184,
	97,  60, 179,  51, 224, 146, 175, 237,
	// Checksum
	11, 165,
}

// 255*24 - SUM(TestVector192[0:23]) = 255*24 - 3139 = 2981
const Checksum192 = "0ba5"

/////////////////////////////////////////////////

func TestChecksum(t *testing.T) {
	// Use test vector and SHA3_256
	h := hasher.SHA3_256.New()
	h.Write([]byte(TestData))
	dat := h.Sum(nil)

	check, err := hex.DecodeString(Checksum256)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	ret := checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	// Use test vector and SHA3_224
	h = hasher.SHA3_224.New()
	h.Write([]byte(TestData))
	dat = h.Sum(nil)

	check, err = hex.DecodeString(Checksum224)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	// Use test vector and SHA3_224, cut down to 192 bits
	h = hasher.SHA3_224.New()
	h.Write([]byte(TestData))
	dat = h.Sum(nil)

	check, err = hex.DecodeString(Checksum192)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	ret = checksum(dat[:24])

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	// Edge cases of all 0's and all 1's for 32, 28 and 24 bytes
	check, err = hex.DecodeString(MaxChecksum256)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	dat = make([]byte, 32)
	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	check, err = hex.DecodeString(MinChecksum)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	for i := range dat {
		dat[i] = 255
	}

	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	check, err = hex.DecodeString(MaxChecksum224)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	dat = make([]byte, 28)
	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	check, err = hex.DecodeString(MinChecksum)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	for i := range dat {
		dat[i] = 255
	}

	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	check, err = hex.DecodeString(MaxChecksum192)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	dat = make([]byte, 24)
	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	check, err = hex.DecodeString(MinChecksum)
	if err != nil {
		t.Fatalf("Error decoding checksum hex string: %s", err)
	}

	for i := range dat {
		dat[i] = 255
	}

	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}

	// Test single byte checksum
	// 100
	dat = []byte{0x64}
	// 255-100 = 155
	check = []byte{0x9b}

	ret = checksum(dat)

	if !bytes.Equal(ret, check) {
		t.Fatalf("Invalid checksum! Got: %x, Expected: %x", ret, check)
	}
}

func testConsistencyParams(params *Params, t *testing.T) {
	key := NewKey(params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test signature consistency
	msg := []byte(TestData)
	key.Generate()
	sig := key.Sign(msg)
	pk := key.GetPK()

	// Check params encoding is first byte of signature
	enc := EncodeParams(params)
	if ParamsEncoding(sig[0]) != enc {
		t.Fatalf("Invalid Params encoding! Got: %d, Expected: %d", sig[0], enc)
	}

	// Check public seed matches next 32 bytes of signature
	sigNoEncode := sig[1:]
	if !bytes.Equal(sigNoEncode[:SeedSize], key.pSeed) {
		t.Fatalf("Invalid Public Seed in signature! Got: %x, Expected: %x", sig[:SeedSize], key.pSeed)
	}

	// Get correct test vector
	sigSlice := sigNoEncode[SeedSize:]
	var compare []uint8
	switch params.m {
	case 32:
		compare = TestVector256
	case 28:
		compare = TestVector224
	case 24:
		compare = TestVector192
	default:
		t.Fatalf("No test vector available for m=%d", params.m)
	}

	// Compare each ladder point of the signature with the corresponding chain according to test vector indexes
	for i := 0; i < params.total; i++ {
		if !bytes.Equal(sigSlice[i*params.n : (i+1)*params.n], key.chains[int(compare[i])][i*params.n : (i+1)*params.n]) {
			t.Fatalf("Invalid signature chain %d! Got: %x, Expected: %x", i,
				sigSlice[i*params.n : (i+1)*params.n], key.chains[int(compare[i])][i*params.n : (i+1)*params.n])
		}
	}

	// Check decode consistency
	ret := make([]byte, 0, PKSize)
	ret = params.Decode(ret, msg, sigNoEncode)

	if !bytes.Equal(ret, pk) {
		t.Fatalf("Key.Sign + Params.Decode are not consistent! Expected PK: %v, Got: %v",
			pk, ret)
	}
}

func TestKey_Sign_Consistency_TestVectors(t *testing.T) {
	// Test all defined parameter types
	for i := ParamsEncoding(0); i < ParamsEncodingLen; i++ {
		testConsistencyParams(DecodeParams(i), t)
	}
}
