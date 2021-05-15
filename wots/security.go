////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import "gitlab.com/xx_network/crypto/hasher"

///////////////////////////////////////////////////////////////////////
// LEVEL0 WOTS+ INSTANTIATION
///////////////////////////////////////////////////////////////////////
// Security Levels
// Classical:    139.30
// Post quantum: 80

// PARAMETERS
// N = 160 bits = 20 bytes
// M = 192 bits = 24 bytes
// PRF HASH = BLAKE2B_256
// MSG Hash = SHA3_224

// Resulting signature size: 4424 bits
///////////////////////////////////////////////////////////////////////
const (
	level0N    = 20
	level0M    = 24
	level0PrfH = hasher.BLAKE2B_256
	level0MsgH = hasher.SHA3_224
)

var level0Params = NewParams(level0N, level0M, level0PrfH, level0MsgH)
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
// LEVEL1 WOTS+ INSTANTIATION
///////////////////////////////////////////////////////////////////////
// Security Levels
// Classical:    171.30
// Post quantum: 96

// PARAMETERS
// N = 192 bits = 24 bytes
// M = 192 bits = 24 bytes
// PRF HASH = BLAKE2B_256
// MSG Hash = SHA3_224

// Resulting signature size: 5256 bits
///////////////////////////////////////////////////////////////////////
const (
	level1N    = 24
	level1M    = 24
	level1PrfH = hasher.BLAKE2B_256
	level1MsgH = hasher.SHA3_224
)

var level1Params = NewParams(level1N, level1M, level1PrfH, level1MsgH)
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
// LEVEL2 WOTS+ INSTANTIATION
///////////////////////////////////////////////////////////////////////
// Security Levels
// Classical:    203.30
// Post quantum: 112
// Note: Post quantum MSG Hash Security is 96, but the message
// is always structured, so CMA doesn't apply

// PARAMETERS
// N = 224 bits = 28 bytes
// M = 192 bits = 24 bytes
// PRF HASH = BLAKE2B_256
// MSG Hash = SHA3_224

// Resulting signature size: 6088 bits
///////////////////////////////////////////////////////////////////////
const (
	level2N    = 28
	level2M    = 24
	level2PrfH = hasher.BLAKE2B_256
	level2MsgH = hasher.SHA3_224
)

var level2Params = NewParams(level2N, level2M, level2PrfH, level2MsgH)
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
// LEVEL3 WOTS+ INSTANTIATION
///////////////////////////////////////////////////////////////////////
// Security Levels
// Classical:    235.30
// Post quantum: 128
// Note: Post quantum MSG Hash Security is 96, but the message
// is always structured, so CMA doesn't apply

// PARAMETERS
// N = 256 bits = 32 bytes
// M = 192 bits = 24 bytes
// PRF HASH = BLAKE2B_256
// MSG Hash = SHA3_224

// Resulting signature size: 6920 bits
///////////////////////////////////////////////////////////////////////
const (
	level3N    = 32
	level3M    = 24
	level3PrfH = hasher.BLAKE2B_256
	level3MsgH = hasher.SHA3_224
)

var level3Params = NewParams(level3N, level3M, level3PrfH, level3MsgH)
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
// CONSENSUS WOTS+ INSTANTIATION
///////////////////////////////////////////////////////////////////////
// Security Levels
// Classical:    234.91
// Post quantum: 128

// PARAMETERS
// N = 256 bits = 32 bytes
// M = 256 bits = 32 bytes
// PRF HASH = BLAKE2B_256
// MSG Hash = SHA3_256

// WARNING: Transactions signed using consensus parameters
// will be discarded, so don't use these for wallets

// Resulting signature size: 8968 bits
///////////////////////////////////////////////////////////////////////
const (
	consensusN    = 32
	consensusM    = 32
	consensusPrfH = hasher.BLAKE2B_256
	consensusMsgH = hasher.SHA3_256
)

var consensusParams = NewParams(consensusN, consensusM, consensusPrfH, consensusMsgH)
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

// Params encoding
type ParamsEncoding uint8

const (
	Level0 ParamsEncoding = iota
	Level1
	Level2
	Level3
	Consensus
)
const (
	ParamsEncodingLen = Consensus + 1 // 5
	DefaultParams = Level0
)

func DecodeParams(enc ParamsEncoding) *Params {
	switch enc {
	case Level0:
		return level0Params
	case Level1:
		return level1Params
	case Level2:
		return level2Params
	case Level3:
		return level3Params
	case Consensus:
		return consensusParams
	default:
		return nil
	}
}

func EncodeParams(p *Params) ParamsEncoding {
	if level0Params.Equal(p) {
		return Level0
	}
	if level1Params.Equal(p) {
		return Level1
	}
	if level2Params.Equal(p) {
		return Level2
	}
	if level3Params.Equal(p) {
		return Level3
	}
	if consensusParams.Equal(p) {
		return Consensus
	}
	// This will decode to nil
	return ParamsEncodingLen
}

func DecodeTransactionSignature(out, msg, signature []byte) []byte {
	// 1. Return if msg or signature is empty
	if len(msg) == 0 || len(signature) == 0 {
		return nil
	}
	// 2. Don't allow consensus params
	encoding := ParamsEncoding(signature[0])
	if encoding == Consensus {
		return nil
	}
	// 3. Decode params
	params := DecodeParams(encoding)
	if params == nil {
		return nil
	}
	// 4. Use correct params to decode signature
	return params.Decode(out, msg, signature[1:])
}
