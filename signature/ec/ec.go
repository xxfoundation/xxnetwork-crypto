////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package ec contains logic for handling elliptic curve keys

package ec

import (
	"crypto/rand"
	"encoding/pem"
	"github.com/katzenpost/core/crypto/eddsa"
)

const (
	privateKeyType = "ED25519 PRIVATE KEY"
	publicKeyType  = "ED25519 PUBLIC KEY"
)

// CreatePrivateKeyPem creates a PEM file from a private key
func CreatePublicKeyPem(key *eddsa.PublicKey) []byte {
	block := &pem.Block{
		Type:  publicKeyType,
		Bytes: key.Bytes(),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}

// CreatePrivateKeyPem creates a PEM file from a private key
func CreatePrivateKeyPem(key *eddsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  privateKeyType,
		Bytes: key.Bytes(),
	}
	pemBytes := pem.EncodeToMemory(block)
	return pemBytes[:len(pemBytes)-1] // Strip newline
}

// LoadPrivateKeyFromByes decodes and produces an Eddsa PrivateKey
func LoadPrivateKeyFromByes(pemBytes []byte) (*eddsa.PrivateKey, error) {
	pk, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	if err = pk.FromBytes(pemBytes); err != nil {
		return nil, err
	}
	return pk, nil
}

// LoadPublicKeyFromString decodes and produces an Eddsa PublicKey from passed in string
func LoadPublicKeyFromString(pemBytes string) (*eddsa.PublicKey, error) {
	pk, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKey := pk.PublicKey()

	if err = pubKey.FromString(pemBytes); err != nil {
		return nil, err
	}

	return pubKey, nil
}

// LoadPublicKeyFromBytes decodes and produces an Eddsa PublicKey from passed in bytes
func LoadPublicKeyFromBytes(pemBytes []byte) (*eddsa.PublicKey, error) {
	pk, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKey := pk.PublicKey()

	if err = pubKey.FromBytes(pemBytes); err != nil {
		return nil, err
	}

	return pubKey, nil
}
