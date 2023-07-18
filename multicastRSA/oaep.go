////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file.                                                       //
// NOTE: This code is largely copied from golang's crypto/rsa package, so it  //
//       is 3-clause and not 2-clause BSD. Unchanged code (excepting type     //
//       modifications) is noted at the bottom of this file.                  //
////////////////////////////////////////////////////////////////////////////////

// oaep.go implemented "multicast" RSA encryption and decryption using
// RSA-OAEP (optimal Asymmetric Encryption Padding) style encrypt and decrypt
// functions. What we mean by multicast in this context is one writer,
// encrypting with the private RSA key, and many readers using the public key
// to decrypt these broadcasts.

// In other words, you usa an RSA Private Key to encrypt and an RSA Public Key
// to decrypt. The public key isn't published, per se, but instead shared
// with the people targeted in the multicast.

// NOTE: WARNING: It is generally not recommended to copy code, especially not
//                crypto code. Do not do this if you can avoid it.
//                We made an exception here because converting public keys to
//                private keys is non-obvious, and the internal checkPub
//                call to check the public is meant to keep e small, which
//                we wished to replicate.

package multicastRSA

import (
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"gitlab.com/xx_network/crypto/large"
)

type PublicKey interface {
	// GetN returns the RSA Public Key modulus
	GetN() *large.Int

	// GetE returns the RSA Public Key exponent
	GetE() int

	// Size returns the modulus size in bytes. Raw signatures and
	// ciphertexts for or by this public key will have the same
	// size.
	Size() int
}

// PrivateKey implements the same interface as public, but with more functions.
type PrivateKey interface {
	PublicKey

	// GetPrimes returns the prime factors of N, which has >= 2 elements
	GetPrimes() []*large.Int

	// GetD returns the private exponent of the RSA Private Key as
	// a large.Int
	GetD() *large.Int

	// GetDp returns D mod (P - 1), or nil if unavailable
	GetDp() *large.Int

	// GetDq returns D mod (Q - 1), or nil if unavailable
	GetDq() *large.Int
}

// EncryptOAEP encrypts the given message with RSA-OAEP using a Private Key
// for multicast RSA.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to encrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
func EncryptOAEP(hash hash.Hash, random io.Reader, priv PrivateKey,
	msg []byte, label []byte) ([]byte, error) {
	if err := checkPub(priv); err != nil {
		return nil, err
	}
	hash.Reset()
	maxPayloadSize := GetMaxPayloadSize(hash, priv)
	if len(msg) > maxPayloadSize {
		return nil, ErrMessageTooLong
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()
	k := priv.Size()
	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}

	mgf1XOR(db, hash, seed)
	mgf1XOR(seed, hash, db)

	m := new(large.Int)
	m.SetBytes(em)
	c := encrypt(new(large.Int), priv, m)

	out := make([]byte, k)
	return c.FillBytes(out), nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP using an RSA Public Key
// for multicast RSA.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New is a reasonable choice.
//
// The label parameter must match the value given when encrypting. See
// EncryptOAEP for details.
func DecryptOAEP(hash hash.Hash, pub PublicKey,
	ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}
	k := pub.Size()
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	c := new(large.Int).SetBytes(ciphertext)
	m := decrypt(new(large.Int), pub, c)

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	// We probably leak the number of leading zeros.
	// It's not clear that we can do anything about this.
	em := m.FillBytes(make([]byte, k))

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i,
			index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0,
			lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1,
			invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, ErrDecryption
	}

	return rest[index+1:], nil
}

func encrypt(c *large.Int, priv PrivateKey, m *large.Int) *large.Int {
	// Instead of m^e mod n we do m^d mod n
	// NOTE: we could do some optimization, e.g., CRT?
	d := priv.GetD()
	n := priv.GetN()
	c.Exp(m, d, n)
	return c
}

func decrypt(m *large.Int, pub PublicKey, c *large.Int) *large.Int {
	// Again, c^e instead of c^d, so c^e -> (m^d)^e = m
	e := large.NewIntFromUInt(uint64(pub.GetE()))
	n := pub.GetN()
	m.Exp(c, e, n)
	return m
}

///////////////////////////////////////////////////////////////////////////////
// --- The following is copied from golang crypto/rsa package. --------------//
///////////////////////////////////////////////////////////////////////////////

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("xx_network/crypto/multicastRSA: " +
	"message too long for RSA public key size")

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("xx_network/crypto/multicastRSA: " +
	"decryption error")

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("xx_network/crypto/multicastRSA: " +
	"verification error")

var (
	errPublicModulus = errors.New("xx_network/crypto/multicastRSA: " +
		"missing public modulus")
	errPublicExponentSmall = errors.New("xx_network/crypto/multicastRSA: " +
		"public exponent too small")
	errPublicExponentLarge = errors.New("xx_network/crypto/multicastRSA: " +
		"public exponent too large")
)

// checkPub sanity checks the public key before we use it.
// We require pub.E to fit into a 32-bit integer so that we
// do not have different behavior depending on whether
// int is 32 or 64 bits. See also
// https://www.imperialviolet.org/2012/03/16/rsae.html.
func checkPub(pub PublicKey) error {
	if pub.GetN() == nil {
		return errPublicModulus
	}
	if pub.GetE() < 2 {
		return errPublicExponentSmall
	}
	if pub.GetE() > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// GetMaxPayloadSize returns the maximum size of a multicastRSA broadcast
// message. The message must be no longer than the length of the public modulus
// minus twice the hash length, minus a further 2.
func GetMaxPayloadSize(hash hash.Hash, key PublicKey) int {
	hash.Reset()
	k := key.Size()
	hashSize := hash.Size()
	return k - 2*hashSize - 2
}
