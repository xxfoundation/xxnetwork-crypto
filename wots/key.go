////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"io"
)

// WOTS+ KEY //
type Key struct {
	// The Secret Keys seed of this WOTS+ Key
	seed []byte
	// The public seed, used to generate random elements
	pSeed []byte
	// The full ladders of a key, once generated
	chains [][]byte
	// Flag to tell if the ladders have been generated
	generated bool
	// The public key
	pk []byte
	// The params of this key
	params *Params
}

///////////////////////////////////////////////////////////////////////
// Constructors

// Creates a WOTS+ key with given params, and uses csprng to read
// random values for the seed and public seed
func NewKey(params *Params, csprng io.Reader) *Key {
	k := &Key{
		seed:   make([]byte, SeedSize),
		pSeed:  make([]byte, SeedSize),
		chains: nil,
		pk:     nil,
		params: params,
	}
	n, err := csprng.Read(k.seed)
	if err != nil || n != SeedSize {
		return nil
	}
	n, err = csprng.Read(k.pSeed)
	if err != nil || n != SeedSize {
		return nil
	}
	return k
}

// Creates a WOTS+ key with given params, and given secret and public seeds
func NewKeyFromSeed(params *Params, seed []byte, pSeed []byte) *Key {
	if len(seed) != SeedSize {
		return nil
	}
	if len(pSeed) != SeedSize {
		return nil
	}

	k := &Key{
		seed:   make([]byte, SeedSize),
		pSeed:  make([]byte, SeedSize),
		chains: nil,
		pk:     nil,
		params: params,
	}
	copy(k.seed, seed)
	copy(k.pSeed, pSeed)
	return k
}

///////////////////////////////////////////////////////////////////////
// Get the Public Key
// Returns nil if not computed yet
func (k *Key) GetPK() []byte {
	return k.pk
}

//////////////////////////////////////////////////////////////////////
// COMPUTE PK
// Compute the PK from this key's seeds, without storing ladder points
// If PK was already computed, return it
func (k *Key) ComputePK() []byte {
	if k.pk != nil {
		return k.pk
	}

	// Get PK by computing all ladders until the end
	k.pk = make([]byte, 0, PKSize)
	k.pk = k.params.computeLadders(k.pk, k.pSeed, nil, k.computeSK(), nil, false)

	return k.pk
}

///////////////////////////////////////////////////////////////////////
// GENERATE
// Generate all the ladder values in order to speed up signing
// If ladders are already generated, simply return
func (k *Key) Generate() {
	if k.generated {
		return
	}

	// Create memory for all ladders
	k.chains = make([][]byte, W)
	for i := range k.chains {
		k.chains[i] = make([]byte, k.params.n * k.params.total)
	}

	// Compute Secret Keys and place them at the beginning of chains memory
	k.chains[0] = k.computeSK()

	// Get PK by computing all ladders until the end, while saving all ladder positions to memory
	k.pk = make([]byte, 0, PKSize)
	k.pk = k.params.computeLadders(k.pk, k.pSeed, nil, k.chains[0], k.chains, false)

	// Set generated flag
	k.generated = true
}

///////////////////////////////////////////////////////////////////////
// SIGN
// Signs an arbitrary length message using the WOTS+ key
// Returns the signature which contains pSeed || ladder elements
// Note: If the key is already generated, this function is fast,
// since it simply hashes the message and then copies the correct
// positions of the ladders
func (k *Key) Sign(msg []byte) []byte {
	// If all ladders have been generated, use fast signing
	if k.generated {
		return k.fastSign(msg)
	}

	// Otherwise, compute the signature from scratch
	// Get the signature by computing ladder points according to message
	signature := k.params.computeLadders(nil, k.pSeed, msg, k.computeSK(), nil, true)

	// Build signature
	return k.buildSignature(signature)
}

func (k *Key) fastSign(msg []byte) []byte {
	// Compute message hash and checksum
	data := k.params.msgHashAndComputeChecksum(msg)

	// Get the signature by copying the ladder positions from memory according to message
	signature := make([]byte, k.params.total * k.params.n)
	for i := 0; i < k.params.total; i++ {
		copy(signature[i * k.params.n: (i+1) * k.params.n], k.chains[int(data[i])][i * k.params.n : (i+1) * k.params.n])
	}

	// Build signature
	return k.buildSignature(signature)
}

func (k *Key) computeSK() []byte {
	// Create secret keys slice
	sks := make([]byte, k.params.n * k.params.total)
	// Get PRF hash
	hPrf := k.params.prfHash.New()
	// Hash buffer
	prfBuffer := make([]byte, 0, hPrf.Size())

	// Compute SK_i = H(SEED || i)
	for i := 0; i < k.params.total; i++ {
		prfBuffer = prf(prfBuffer, hPrf, k.seed, uint8(i))
		copy(sks[i*k.params.n:(i+1)*k.params.n], prfBuffer[0:k.params.n])
		prfBuffer = prfBuffer[:0]
	}
	return sks
}

func (k *Key) buildSignature(sig []byte) []byte {
	encode := EncodeParams(k.params)
	// Signature is composed by
	// ParamsEncoding, 1 byte
	// Public Seed,    32 bytes
	// Ladder points,  Total*n bytes
	signature := make([]byte, 1 + SeedSize + len(sig))
	signature[0] = byte(encode)
	copy(signature[1:1+SeedSize], k.pSeed)
	copy(signature[1+SeedSize:], sig)
	return signature
}
