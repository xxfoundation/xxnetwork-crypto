////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"fmt"
	"gitlab.com/xx_network/crypto/hasher"
)

// WOTS+ implementation with compression parameter of Wbits = 8
// This means that each byte of the message has one ladder of depth W=2^Wbits=256
// WARNING: Changing this parameter leads to unexpected results!
const W = 256

// The size of WOTS+ Public Keys if fixed to 32 bytes
const PKSize = 32

// The hash function used to calculate the public key
// using a tweakable hash function construction is fixed
const PKHash = hasher.SHA3_256

// The size of WOTS+ secret and public seeds is fixed to 32 bytes
const SeedSize = 32

// Notes about parameter restrictions
// The number of message ladders is computed as numLadders = m*8/Wbits = m, for Wbits=8
// The number of checksum ladders is computed as floor(log2((W-1)*numLadders)/Wbits) + 1
// This basically will be the number of bytes needed to store the maximum checksum value possible of m*(W-1)
// If m=1, meaning we are signing 1 byte, then the checksum is 1 byte as well
// For higher values of m, the checksum fits in 2 bytes, until m=258, where 3 bytes become necessary
// Since we don't except to ever need to sign a message as large as 258 bytes
// we can assume that 1 <= m <= 257 and set checksum as 1 or 2 bytes accordingly
// This way we compute total ladders as:
// if m == 1 -> total = m + 1 = 2
// if m > 1 && m <= 257 -> total = m + 2
// Furthermore, when using ladder indexes or depths in hash functions, we want to fit the indexes in 1 byte
// for efficiency. Since W is hardcoded to 256, possible depths are always 0 to 255, fully covering the
// range of 1 byte values. On another hand, this means that the total number of ladders is limited to 256 as
// well, so that the ladder index also ranges between 0 and 255
// This imposes an extra restriction on the size m, since total <= 256, which is equivalent to m <= 254
const MaxMsgSize = 254

// WOTS+ parameters //
type Params struct {
	// The size of the secret keys and ladder points
	n int
	// The size of the message to be signed (after being hashed)
	m int
	// The hash function to use for PRF
	prfHash hasher.Hasher
	// The hash function to use for the message
	msgHash hasher.Hasher
	// The total number of ladders
	total int
}

///////////////////////////////////////////////////////////////////////
// Constructor

// Creates WOTS+ params with given values of n, m; prf and msg hashes
func NewParams(n, m int, prf, msg hasher.Hasher) *Params {
	// Don't allow creation of params if m == 0 or m > MaxMsgSize
	if m < 1 || m > MaxMsgSize {
		return nil
	}
	// Don't allow creation of params if hash functions sizes are smaller than specified N and M
	if prf.Size() < n || msg.Size() < m {
		return nil
	}
	checksumLadders := 2
	// The only case that we need just 1 checksum ladder is for m=1
	if m == 1 {
		checksumLadders = 1
	}
	return &Params{
		n:       n,
		m:       m,
		prfHash: prf,
		msgHash: msg,
		total:   m + checksumLadders,
	}
}

///////////////////////////////////////////////////////////////////////
// Stringer interface
func (p *Params) String() string {
	return fmt.Sprintf("N: %d, M: %d, PRF: %s, MSG: %s", p.n, p.m, p.prfHash, p.msgHash)
}

///////////////////////////////////////////////////////////////////////
// Comparison
func (p *Params) Equal(other *Params) bool {
	return p.n == other.n && p.m == other.m && p.prfHash == other.prfHash && p.msgHash == other.msgHash
}

///////////////////////////////////////////////////////////////////////
// Implement Decoder interface
///////////////////////////////////////////////////////////////////////
// Decode a signature, i.e., compute the public key from the message and signature
func (p *Params) Decode(out, msg, signature []byte) []byte {
	// Ensure signature has correct size
	siglen := p.total * p.n + SeedSize
	if len(signature) != siglen {
		return nil
	}

	// Ensure output slice is well formed
	if len(out) != 0 || cap(out) != PKSize {
		return nil
	}

	// Get public seed from first 32 bytes of the signature
	pSeed := signature[0:SeedSize]
	signature = signature[SeedSize:]

	// Compute the public key from message and signature
	return p.computeLadders(out, pSeed, msg, signature, nil, false)
}

///////////////////////////////////////////////////////////////////////

// Hash Message, Compute Checksum and Append it
func (p *Params) msgHashAndComputeChecksum(msg []byte) []byte {
	// Hash the message
	hMsg := p.msgHash.New()
	msgBuffer := make([]byte, 0, hMsg.Size())
	hashedMsg := make([]byte, p.m)
	hMsg.Write(msg)
	msgBuffer = hMsg.Sum(msgBuffer)
	copy(hashedMsg[0:p.m], msgBuffer[0:p.m])
	// Calculate and append checksum
	return append(hashedMsg, checksum(hashedMsg)...)
}

// Go down the ladders and calculate PK or signature
// There are 4 possible scenarios to call this method:
// 1. ComputePK() - Compute the Public Key without storing any data in memory
// 2. Generate() - Compute Public Key storing all the ladder points in memory
// 3. Decode() - Decode a signature starting from the message + Compute Public Key without storing any data in memory
// 4. Sign() - Signs a message + Returns the Signature without storing any data in memory
func (p *Params) computeLadders(out, pSeed, msg, points []byte, chains [][]byte, sign bool) []byte {

	// If SIGN() or DECODE()
	var start []byte
	if msg != nil {
		start = p.msgHashAndComputeChecksum(msg)

	// If GENERATE() or ComputePK()
	} else {
		// Set start array with beginning of each ladder (0s when computing)
		start = make([]byte, p.total)
	}

	// Get Hashes
	// PRF
	hPrf := p.prfHash.New()
	// Tweak and Public Key
	hTweak := PKHash.New()

	// Hash buffer
	prfBuffer := make([]byte, 0, hPrf.Size())

	// Compute random elements
	rands := computeRands(p.n, pSeed, hPrf)

	// Chains memory
	value := make([]byte, p.n)

	// Save output values
	var outputs []byte
	if chains != nil {
		outputs = chains[W-1]
	} else {
		outputs = make([]byte, p.n * p.total)
	}

	// index
	begin := uint8(0)
	end := uint8(0)
	for i := 0; i < p.total; i++ {

		// Initialize value with the relevant ladder from the signature OR Secret Keys
		copy(value, points[i * p.n : (i+1) * p.n])

		// If SIGN()
		if sign {
			begin = 0
			end = start[i]
		} else {
			begin = start[i]
			end = W-1
		}

		// Go down the ladder
		for j := begin; j < end; j++ {

			// Perform masking of the value by XORing it with the correct random element
			for z, val := range value {
				value[z] = rands[j][z] ^ val
			}

			// Chain the value. value = H(PKSEED || j || masked value)
			prfBuffer = chain(prfBuffer, hPrf, pSeed, j+1, value)
			copy(value, prfBuffer[0:p.n])
			prfBuffer = prfBuffer[:0]

			// If GENERATE()
			if chains != nil {
				// Save in memory for all ladders
				copy(chains[int(j) + 1][i * p.n : (i+1) * p.n], value)
			}
		}

		// If chains passed as nil copy values to outputs
		if chains == nil {
			copy(outputs[i * p.n : (i+1) * p.n], value)
		}

		// If GENERATE() or DECODE() or ComputePK()
		if !sign {
			// Calculate tweak
			if parity(value) {
				hTweak.Write(value)
			}
		}

	}

	// If GENERATE() or DECODE() or ComputePK()
	if !sign {
		// Tweak
		tweak := hTweak.Sum(nil)

		// H(PSeed || T || pk1...pk)
		// pk1...pk are placed in outputs slice
		hTweak.Reset()
		hTweak.Write(pSeed)
		hTweak.Write(tweak)
		hTweak.Write(outputs)

		// Compute PK by performing the hash sum
		return hTweak.Sum(out)
	}

	// If SIGN()
	return outputs
}
