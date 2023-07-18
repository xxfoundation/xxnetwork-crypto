////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package ec

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
)

const (
	privKeyEncoded = `uVAt6d+y3XW699L3THlcoTA2utw2dhoqnX6821x6OcnOliwX84eajmp45IZ+STw0dUl8uJtZwDKDuHVX6ZpGzg==`
	expectedPubKey = `ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=`
	pubKeyEncoded  = `zpYsF/OHmo5qeOSGfkk8NHVJfLibWcAyg7h1V+maRs4=`
)

type CountingReader struct {
	count uint8
}

// Read just counts until 254 then starts over again
func (c *CountingReader) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		c.count = (c.count + 1) % 255
		b[i] = c.count
	}
	return len(b), nil
}

// Smoke test
func TestEcSmoke(t *testing.T) {
	expectedPrivKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100}
	expectedSignature := []byte{204, 79, 186, 189, 202, 122, 200, 108, 253, 120, 62, 65, 106, 208, 125, 17, 113, 73, 144, 66, 239, 71, 65, 250, 247, 107, 116, 116, 224, 228, 59, 90, 195, 6, 184, 43, 241, 149, 110, 80, 108, 75, 70, 220, 196, 100, 191, 82, 183, 91, 229, 164, 235, 148, 75, 207, 53, 48, 22, 42, 238, 97, 119, 0}

	data := []byte("Secret message, do not read")

	// Generate a mock EC keypair with pre-determined data
	notRand := &CountingReader{count: 0}
	privKey, err := NewKeyPair(notRand)
	if err != nil {
		t.Fatalf("EC Smoke test error: "+
			"Could not generate key: %v", err)
	}

	// Check key matches predetermined data
	if !bytes.Equal(privKey.privKey[:], expectedPrivKey) {
		t.Fatalf("Unexpected private key generated."+
			"\nexpected: %v\nreceived: %v", expectedPrivKey, privKey)
	}

	// Generate a signature
	signature := Sign(privKey, data)

	// Check signature matches predetermined data
	if !bytes.Equal(expectedSignature, signature) {
		t.Fatalf("Unexpected signature generated."+
			"\nexpected: %v\nreceived: %v", expectedSignature, signature)

	}

	// Check that the signature is verified properly
	publicKey := privKey.GetPublic()
	if !Verify(publicKey, data, signature) {
		t.Fatalf("EC Smoke test error: " +
			"Could not verify signature.")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	expected, err := NewKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("LoadPrivateKey error: "+
			"Failed to create a test key: %v", err)
	}

	err = expected.UnmarshalText(privKeyEncoded)
	if err != nil {
		t.Fatalf("LoadPrivateKey error: "+
			"Failed to load public key string into object: %v", err)
	}

	received, err := LoadPrivateKey(privKeyEncoded)
	if err != nil {
		t.Fatalf("LoadPrivateKey error: "+
			"Failed to load public key from string: %v", err)
	}

	if !reflect.DeepEqual(received, expected) {
		t.Fatalf("Unexpected private key.\nexpected: %s\nreceived: %s",
			expected, received)
	}

	encoded := received.MarshalText()
	if encoded != privKeyEncoded {
		t.Fatalf("Unexpected encoded private key.\nexpected: %q\nreceived: %q",
			privKeyEncoded, encoded)
	}

}

// Error path
func TestLoadPrivateKeyFromString_Error(t *testing.T) {
	_, err := LoadPrivateKey("invalid")
	if err == nil {
		t.Errorf("LoadPrivateKey error path failed, " +
			"should be invalid eddsa key")
	}

	_, err = LoadPrivateKey(pubKeyEncoded)
	if err == nil {
		t.Errorf("LoadPrivateKey error path failed, " +
			"should be invalid eddsa key")
	}
}

// Happy path
func TestLoadPublicKey(t *testing.T) {
	pk, err := NewKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("LoadPublicKey error: "+
			"Failed to create a test key: %v", err)
	}

	expected := pk.GetPublic()
	err = expected.UnmarshalText(pubKeyEncoded)
	if err != nil {
		t.Fatalf("LoadPublicKey error: "+
			"Failed to load public key string into object: %v", err)
	}

	received, err := LoadPublicKey(pubKeyEncoded)
	if err != nil {
		t.Fatalf("LoadPublicKey error: "+
			"Failed to load public key from string: %v", err)
	}

	if !reflect.DeepEqual(received, expected) {
		t.Fatalf("Unexpected public key.\nexpected: %s\nreceived: %s",
			expected, received)
	}

	encoded := received.MarshalText()
	if encoded != pubKeyEncoded {
		t.Fatalf("Unexpected marshalled public key."+
			"\nexpected: %q\nreceived: %q", pubKeyEncoded, encoded)
	}

}

// Error path: Tests that LoadPublicKey returns an error when the key is not
// base 64 encoded.
func TestLoadPublicKeyFromString_InvalidBase64Error(t *testing.T) {
	_, err := LoadPublicKey("invalid")
	if err == nil {
		t.Errorf("Expected error for invalid key.")
	}
}

// Error path: Tests that LoadPublicKey returns an error when passing in a
// private key instead of a public key.
func TestLoadPublicKeyFromString_PrivateKeyError(t *testing.T) {
	_, err := LoadPublicKey(privKeyEncoded)
	if err == nil || !strings.Contains(err.Error(), invalidKeySize) {
		t.Errorf("Unexpected error when trying to load a private key."+
			"\nexpected: %s\nreceived: %+v", invalidKeySize, err)
	}
}

// Unit test of both PublicKey.KeyType and PrivateKey.KeyType.
func TestKeyTYpe(t *testing.T) {
	pk, err := NewKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("LoadPublicKey error: "+
			"Failed to create a test key: %v", err)
	}

	if pk.KeyType() != keyType {
		t.Errorf("Unexpected private key type string."+
			"\nexpected: %s\nreceived: %s", keyType, pk.KeyType())
	}

	publicKeyKeyType := pk.GetPublic().KeyType()
	if publicKeyKeyType != keyType {
		t.Errorf("Unexpected public key type string."+
			"\nexpected: %s\nreceived: %s", keyType, publicKeyKeyType)
	}
}

// Unit test of both PublicKey.Marshal and PrivateKey.Marshal.
func TestMarshal(t *testing.T) {
	pk, err := NewKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create a test key: %+v", err)
	}

	if !bytes.Equal(pk.Marshal(), pk.privKey[:]) {
		t.Errorf("Unexpected marshalled public key."+
			"\nepected: %v\nreceived: %v", pk.privKey, pk.Marshal())
	}

	publicKey := pk.GetPublic()
	if !bytes.Equal(publicKey.Marshal(), pk.pubKey.pubKey[:]) {
		t.Errorf("Unexpected marshalled public key."+
			"\nepected: %v\nreceived: %v", pk.pubKey.pubKey, publicKey.Marshal())
	}

}

// Smoke test
func TestPublicKey_String(t *testing.T) {
	notRand := &CountingReader{count: 0}

	pk, err := NewKeyPair(notRand)
	if err != nil {
		t.Fatalf("LoadPublicKey error: "+
			"Failed to create a test key: %v", err)
	}

	publicKey := pk.GetPublic()

	if publicKey.String() != expectedPubKey {
		t.Errorf("Unexpected PublicKey string."+
			"\nexpected: %s\nreceived: %s", pubKeyEncoded, publicKey.String())
	}
}
