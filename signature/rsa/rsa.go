////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package rsa includes wrappers to sign and verify the signatures of messages
// with the PKCS#1 RSASSA-PSS signature algorithm:
// https://tools.ietf.org/html/rfc3447#page-29
//
// We use this because of the "tighter" security proof and regression to full
// domain hashing in cases where good RNG is unavailable.
//
// The primary reason for wrapping is to interface with the large Int api
// used by cMix.
package rsa

import (
	"crypto"
	gorsa "crypto/rsa"
	"encoding/binary"
	"io"
	"math/big"

	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/xx_network/crypto/large"
	_ "golang.org/x/crypto/blake2b"
)

// minRSABitLen is the recommended minimum RSA key length allowed in production.
// Use of any bit length smaller than this will result in a warning log print.
var minRSABitLen = 3072

const (
	minRSABitLenWarn = "CAUTION! RSA bit length %d is smaller than" +
		"the recommended minimum of %d bits. This is" +
		"insecure; do not use in production!"
	ELength = 4
)

// Options wraps [PSSOptions].
type Options struct {
	gorsa.PSSOptions
}

// PrivateKey is identical to the RSA private key, with additional [big.Int]
// access functions.
type PrivateKey struct {
	gorsa.PrivateKey
}

// GetD returns the private exponent of the RSA Private Key as a [large.Int].
func (p *PrivateKey) GetD() *large.Int {
	return large.NewIntFromBigInt(p.D)
}

// GetPrimes returns the prime factors of N, which has >= 2 elements.
func (p *PrivateKey) GetPrimes() []*large.Int {
	primes := make([]*large.Int, len(p.Primes))
	for i := 0; i < len(p.Primes); i++ {
		primes[i] = large.NewIntFromBigInt(p.Primes[i])
	}
	return primes
}

// GetDp returns D mod (P - 1), or nil if unavailable.
func (p *PrivateKey) GetDp() *large.Int {
	if p.Precomputed.Dp == nil {
		return nil
	}
	return large.NewIntFromBigInt(p.Precomputed.Dp)
}

// GetDq returns D mod (Q - 1), or nil if unavailable.
func (p *PrivateKey) GetDq() *large.Int {
	if p.Precomputed.Dq == nil {
		return nil
	}
	return large.NewIntFromBigInt(p.Precomputed.Dq)
}

// GetPublic returns the public key in *rsa.PublicKey format.
func (p *PrivateKey) GetPublic() *PublicKey {
	return &PublicKey{p.PublicKey}
}

// // NOTE: This is included for completeness, but since we don't use the multi
// // configuration, the CRTValues struct inside the PrivateKey should always be
// // empty for our purposes. Leaving this present and commented to document that
// // fact.
//
// // CRTValue holds Exp, Coeff, R as large.Int's
// type CRTValue struct {
// 	Exp   *large.Int // D mod (prime-1).
// 	Coeff *large.Int // R·Coeff ≡ 1 mod Prime.
// 	R     *large.Int // product of primes prior to this (inc p and q).
// }
//
// // GetCRTValues returns large.Int versions of all precomputed chinese
// // remainder theorem values
// func (priv *PrivateKey) GetCRTValues() []*CRTValue {
// 	if priv.Precomputed.CRTValues == nil {
// 		return nil
// 	}
// 	crtValues := make([]*CRTValue, len(priv.Precomputed.CRTValues))
// 	for i := 0; i < len(priv.Precomputed.CRTValues); i++ {
// 		cur := priv.Precomputed.CRTValues[i]
// 		crtValues[i] = &CRTValue{
// 			Exp:   large.NewIntFromBigInt(cur.Exp),
// 			Coeff: large.NewIntFromBigInt(cur.Coeff),
// 			R:     large.NewIntFromBigInt(cur.R),
// 		}
// 	}
// 	return crtValues
// }

// PublicKey is identical to the RSA public key with additional [big.Int] access
// functions.
type PublicKey struct {
	gorsa.PublicKey
}

// Public returns the public key corresponding to the private key.
func (p *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{p.PublicKey}
}

// GetN returns the RSA public key modulus.
func (p *PrivateKey) GetN() *large.Int {
	return large.NewIntFromBigInt(p.N)
}

// GetE returns the RSA public key exponent.
func (p *PrivateKey) GetE() int {
	return p.E
}

// Bytes returns the [PublicKey] as a byte slice.
// The first 4 bytes are the exponent (E) as a 4 byte big
// endian integer, followed by the modulus (N) as a [big.Int]
// in Bytes format. We chose the 32-bit integer for E
// because it should be big enough.
func (p *PublicKey) Bytes() []byte {
	buf := make([]byte, ELength)
	binary.BigEndian.PutUint32(buf, uint32(p.GetE()))
	return append(buf, p.PublicKey.N.Bytes()...)
}

// FromBytes loads the given byte slice into the [PublicKey].
func (p *PublicKey) FromBytes(b []byte) error {
	e := binary.BigEndian.Uint32(b[:ELength])
	p.E = int(e)
	p.N = new(big.Int)
	p.N.SetBytes(b[ELength:])
	return nil
}

// GetN returns the RSA public key modulus.
func (p *PublicKey) GetN() *large.Int {
	return large.NewIntFromBigInt(p.N)
}

// GetE returns the RSA public key exponent.
func (p *PublicKey) GetE() int {
	return p.E
}

// GetGoRSA returns the public key in the standard Go crypto/rsa format.
func (p *PublicKey) GetGoRSA() *gorsa.PublicKey {
	return &p.PublicKey
}

// GenerateKey generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	if bits < minRSABitLen {
		jww.WARN.Printf(minRSABitLenWarn, bits, minRSABitLen)
	}

	pk, err := gorsa.GenerateMultiPrimeKey(random, 2, bits)
	return &PrivateKey{*pk}, err
}

// NewDefaultOptions returns signing options that set the salt length equal
// to the length of the hash and uses the default cMix Hash algorithm.
func NewDefaultOptions() *Options {
	return &Options{
		gorsa.PSSOptions{
			SaltLength: gorsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.BLAKE2b_256,
		},
	}
}

// Sign uses RSASSA-PSS to calculate the signature of hashed. Note
// that hashed must be the result of hashing the input message using the
// given hash function. The opts argument may be nil, in which case
// the default cMix hash and salt length == size of the hash are used.
func Sign(rand io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte,
	opts *Options) ([]byte, error) {
	if opts == nil {
		opts = NewDefaultOptions()
		opts.Hash = hash
	}

	return gorsa.SignPSS(rand, &priv.PrivateKey, hash, hashed,
		&opts.PSSOptions)
}

// Verify verifies a PSS signature. hashed is the result of hashing
// the input message using the given hash function and sig is the
// signature. A valid signature is indicated by returning a nil
// error. The opts argument may be nil, in which case the default cMix hash
// and salt length == size of the hash are used.
func Verify(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte,
	opts *Options) error {
	if opts == nil {
		opts = NewDefaultOptions()
		opts.Hash = hash
	}

	return gorsa.VerifyPSS(&pub.PublicKey, hash, hashed, sig,
		&opts.PSSOptions)
}

// IsValidSignature approximates whether the signature looks valid
// by comparing the length of the signature to the length of the public key
func IsValidSignature(pubKey *PublicKey, signature []byte) bool {
	if pubKey == nil {
		return false
	}
	return len(signature) == pubKey.Size()
}
