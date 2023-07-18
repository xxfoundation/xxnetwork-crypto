////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package ec contains logic for handling elliptic curve keys
package ec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

const (
	// PublicKeySize is the size of a serialized PublicKey in bytes (32 bytes).
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a serialized PrivateKey in bytes (64 bytes).
	PrivateKeySize = ed25519.PrivateKeySize

	// Error returned when passed in data is unable to be unmarshalled
	invalidKeySize = "invalid EC key size"

	// Type of key this package will adhere to
	keyType = "ed25519"
)

// PublicKey is a wrapper of [ed25519.PublicKey] that provides additional
// functionality on top of Go's library.
type PublicKey struct {
	pubKey ed25519.PublicKey
}

// MarshalText returns a base64 encoded string of the PublicKey.
// Adheres to the encoding.TextMarshaler interface.
func (pub *PublicKey) MarshalText() string {
	return base64.StdEncoding.EncodeToString(pub.pubKey[:])
}

// UnmarshalText deserializes a base64-encoded string into the PublicKey.
// Adheres to the TextMarshaler interface defined
// in https://golang.org/pkg/encoding/
func (pub *PublicKey) UnmarshalText(data string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	return pub.Unmarshal(keyBytes)
}

// Unmarshal deserializes a byte slice into the PrivateKey
func (pub *PublicKey) Unmarshal(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New(invalidKeySize)
	}

	copy(pub.pubKey[:], data[:])
	return nil
}

// Marshal serializes a PublicKey into a byte slice
func (pub *PublicKey) Marshal() []byte {
	return pub.pubKey[:]
}

// DeepCopy returns a new PublicKey with identical data
// as this PublicKey
func (pub *PublicKey) DeepCopy() *PublicKey {
	data := make([]byte, PublicKeySize)
	copy(data[:], pub.pubKey[:])

	return &PublicKey{pubKey: data}

}

// Stringer function for PublicKey
func (pub *PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(pub.pubKey[:])
}

// KeyType returns the PublicKey type
// as a string. For this case, it will
// be the constant "edd25519
// in this case the constant variable
// whose value is "ed25519".
func (pub *PublicKey) KeyType() string {
	return keyType
}

// PrivateKey is a wrapper of  containing both an ed25519 private key
// and its associated public key. Wrapper provides additional functionality
// on top of Go's library
type PrivateKey struct {
	privKey ed25519.PrivateKey
	pubKey  PublicKey
}

// MarshalText returns a base64 encoded string of the PrivateKey.
// Adheres to the TextMarshaler interface defined
// in https://golang.org/pkg/encoding/
func (priv *PrivateKey) MarshalText() string {
	return base64.StdEncoding.EncodeToString(priv.privKey[:])
}

// UnmarshalText deserializes a base64-encoded string into the PrivateKey.
// Adheres to the TextMarshaler interface defined
// in https://golang.org/pkg/encoding/
func (priv *PrivateKey) UnmarshalText(data string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	return priv.Unmarshal(keyBytes)
}

// Unmarshal deserializes a byte slice into the PrivateKey
func (priv *PrivateKey) Unmarshal(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New(invalidKeySize)
	}

	// Set public and private key values
	priv.privKey = make([]byte, PrivateKeySize)
	copy(priv.privKey[:], data[:])
	priv.pubKey.pubKey = priv.privKey.Public().(ed25519.PublicKey)

	return nil
}

// Marshal serializes a PrivateKey into a byte slice
func (priv *PrivateKey) Marshal() []byte {
	data := make([]byte, PrivateKeySize)
	copy(data[:], priv.privKey[:])

	return data[:]
}

// KeyType returns the PrivateKey type
// as a string. For this case, it will
// be the constant "edd25519
// in this case the constant variable
// whose value is "ed25519".
func (priv *PrivateKey) KeyType() string {
	return keyType
}

// Stringer function for PrivateKey
func (priv *PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(priv.privKey[:])
}

// GetPublic returns a copy of PrivateKey's PublicKey
func (priv *PrivateKey) GetPublic() *PublicKey {
	return priv.pubKey.DeepCopy()
}

// NewKeyPair creates an ed25519 keypair wrapped around
// a PrivateKey, using the random source (for example, crypto/rand.Reader).
func NewKeyPair(rand io.Reader) (*PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return &PrivateKey{}, err
	}

	return &PrivateKey{
		privKey: priv,
		pubKey:  PublicKey{pubKey: pub},
	}, nil
}

// Sign signs the message msg with the PrivateKey and returns the signature.
func Sign(priv *PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv.privKey, msg)
}

// Verify verifies the message msg against the provided
// PublicKey and signature sig
func Verify(pub *PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub.pubKey, msg, sig)
}

// LoadPublicKey loads a base64 string into a PublicKey
func LoadPublicKey(data string) (*PublicKey, error) {
	privKey, err := NewKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKey := privKey.GetPublic()
	if err = pubKey.UnmarshalText(data); err != nil {
		return nil, err
	}

	return pubKey, nil
}

// LoadPrivateKey loads a base64 string into a PrivateKey
func LoadPrivateKey(data string) (*PrivateKey, error) {
	privKey, err := NewKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Unmarshal the
	if err = privKey.UnmarshalText(data); err != nil {
		return nil, err
	}

	return privKey, nil
}
