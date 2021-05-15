////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"bytes"
	"crypto/rand"
	"gitlab.com/xx_network/crypto/hasher"
	"testing"
)

func TestDecodeParams(t *testing.T) {
	// Decode level0 params
	params := DecodeParams(Level0)

	if !params.Equal(level0Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level0Params)
	}

	// Decode level1 params
	params = DecodeParams(Level1)

	if !params.Equal(level1Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level1Params)
	}

	// Decode level2 params
	params = DecodeParams(Level2)

	if !params.Equal(level2Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level2Params)
	}

	// Decode level3 params
	params = DecodeParams(Level3)

	if !params.Equal(level3Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level3Params)
	}

	// Decode consensus params
	params = DecodeParams(Consensus)

	if !params.Equal(consensusParams) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, consensusParams)
	}

	// Decode random params
	params = DecodeParams(ParamsEncodingLen)

	if params != nil {
		t.Fatalf("DecodeParams() should return nil for invalid params encoding")
	}
}

func TestEncodeParams(t *testing.T) {
	// Encode level0 params
	enc := EncodeParams(level0Params)

	if enc != Level0 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level0)
	}

	// Encode level1 params
	enc = EncodeParams(level1Params)

	if enc != Level1 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level1)
	}

	// Encode level2 params
	enc = EncodeParams(level2Params)

	if enc != Level2 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level2)
	}

	// Encode level3 params
	enc = EncodeParams(level3Params)

	if enc != Level3 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level3)
	}

	// Encode consensus params
	enc = EncodeParams(consensusParams)

	if enc != Consensus {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Consensus)
	}

	// Encode random params
	params := NewParams(24, 32, hasher.SHA2_256, hasher.BLAKE2B_256)
	enc = EncodeParams(params)

	if enc != ParamsEncodingLen {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, ParamsEncodingLen)
	}
}

func TestDecodeTransactionSignature(t *testing.T) {
	key := NewKey(level0Params, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test decoding
	msg := make([]byte, 256)
	n, err := rand.Read(msg)

	if err != nil {
		t.Fatalf("Error reading random bytes for msg: %s", err)
	}

	if n != 256 {
		t.Fatalf("Reader only gave us %d bytes, expected 256", n)
	}

	sig := key.Sign(msg)
	pk := key.ComputePK()

	ret := make([]byte, 0, PKSize)
	ret = DecodeTransactionSignature(ret, msg, sig)

	if !bytes.Equal(ret, pk) {
		t.Fatalf("Key.Sign + DecodeTransactionSignature are not consistent! Got: %x, expected: %x",
			ret, pk)
	}

	// Test wrong inputs
	ret = ret[:0]
	ret = DecodeTransactionSignature(ret, nil, sig)

	if ret != nil {
		t.Fatalf("DecodeTransactionSignature() should return nil for invalid message")
	}

	ret = DecodeTransactionSignature(ret, msg, nil)

	if ret != nil {
		t.Fatalf("DecodeTransactionSignature() should return nil for invalid signature")
	}

	// Test attempting to decode a signature with consensus params
	key = NewKey(consensusParams, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	sig = key.Sign(msg)
	ret = DecodeTransactionSignature(ret, msg, sig)

	if ret != nil {
		t.Fatalf("DecodeTransactionSignature() should return nil if signature used consensus params")
	}

	// Test attempting to decode a signature with unknown params
	key = NewKey(NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256), rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	sig = key.Sign(msg)
	ret = DecodeTransactionSignature(ret, msg, sig)

	if ret != nil {
		t.Fatalf("DecodeTransactionSignature() should return nil if signature used unkwown params")
	}
}
