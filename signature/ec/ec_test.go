////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ec

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"github.com/katzenpost/core/crypto/eddsa"
	"reflect"
	"testing"
)

const (
	privKeyEncoded = `uVAt6d+y3XW699L3THlcoTA2utw2dhoqnX6821x6OcnOliwX84eajmp45IZ+STw0dUl8uJtZwDKDuHVX6ZpGzg==`
	privKeyPem     = `-----BEGIN ED25519 PRIVATE KEY-----
uVAt6d+y3XW699L3THlcoTA2utw2dhoqnX6821x6OcnOliwX84eajmp45IZ+STw0
dUl8uJtZwDKDuHVX6ZpGzg==
-----END ED25519 PRIVATE KEY-----`
	pubKeyEncoded = `zpYsF/OHmo5qeOSGfkk8NHVJfLibWcAyg7h1V+maRs4=`
	pubKeyPem     = `-----BEGIN ED25519 PUBLIC KEY-----
zpYsF/OHmo5qeOSGfkk8NHVJfLibWcAyg7h1V+maRs4=
-----END ED25519 PUBLIC KEY-----`
	pubKeyStr = `zpYsF/OHmo5qeOSGfkk8NHVJfLibWcAyg7h1V+maRs4=`
)

// Happy path
func TestUnmarshalEllipticPublicKey(t *testing.T) {
	// Create a mock key
	key, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create a test key: %v", err)
	}

	expectedPublicKey := key.PublicKey()

	// Pass the marshalled public key into a string
	publicKey, err := UnmarshalEllipticPublicKey(expectedPublicKey.String())
	if err != nil {
		t.Fatalf("Could not unmarshal key: %v", err)
	}

	if !reflect.DeepEqual(publicKey, expectedPublicKey) {
		t.Fatalf("Unmarshalled public key did not match expected resutl."+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expectedPublicKey, publicKey)
	}

}

// Error path
func TestUnmarshalEllipticPublicKey_Error(t *testing.T) {
	notValid := "notValid"
	_, err := UnmarshalEllipticPublicKey(notValid)
	if err == nil {
		t.Fatalf("Expected error path: Key [%s] should not be a valid, parseable key", notValid)
	}
}

// Happy path
func TestCreatePrivateKeyPem(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(privKeyEncoded)
	if err != nil {
		t.Fatalf("Failed to parse pem str: %v", err)
	}

	pk, err := LoadPrivateKeyFromByes(decoded)
	if err != nil {
		t.Errorf("%v", err)
	}

	expected := []byte(privKeyPem)

	pemOut := CreatePrivateKeyPem(pk)
	if bytes.Compare(pemOut, expected) != 0 {
		t.Errorf("Private Key Mismatch:"+
			"\n\tExpected: %v"+
			"\n\tReceived: %v",
			expected, pemOut)
	}
}

// Error path
func TestLoadPrivateKeyFromByes_Error(t *testing.T) {
	_, err := LoadPrivateKeyFromByes([]byte("invalid"))
	if err == nil {
		t.Errorf("Expected error path, should be invalid eddsa key")
	}

}

// Error path
func TestLoadPublicKeyFromByes_Error(t *testing.T) {
	_, err := LoadPublicKeyFromBytes([]byte("invalid"))
	if err == nil {
		t.Errorf("Expected error path, should be invalid eddsa key")
	}
}

// Happy path
func TestCreatePublicKeyPem(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(pubKeyEncoded)
	if err != nil {
		t.Fatalf("Failed to parse pem str: %v", err)
	}

	pubKey, err := LoadPublicKeyFromBytes(decoded)
	if err != nil {
		t.Errorf("%v", err)
	}

	received := CreatePublicKeyPem(pubKey)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}

	expected := []byte(pubKeyPem)
	if bytes.Compare(received, expected) != 0 {
		t.Errorf("Private Key Mismatch:"+
			"\n\tExpected: %v"+
			"\n\tReceived: %v",
			expected, received)
	}

}

// Happy path
func TestLoadPublicKeyFromString(t *testing.T) {
	pk, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create a test key: %v", err)
	}

	expected := pk.PublicKey()
	err = expected.FromString(pubKeyStr)
	if err != nil {
		t.Fatalf("Failed to load public key string into object: %v", err)
	}

	received, err := LoadPublicKeyFromString(pubKeyStr)
	if err != nil {
		t.Fatalf("Failed to load public key from string: %v", err)
	}

	if !reflect.DeepEqual(received, expected) {
		t.Fatalf("Unexpected key mismatch."+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expected, received)
	}

}

// Error path
func TestLoadPublicKeyFromString_Error(t *testing.T) {
	_, err := LoadPublicKeyFromString("invalid")
	if err == nil {
		t.Errorf("Expected error path, should be invalid eddsa key")
	}
}
