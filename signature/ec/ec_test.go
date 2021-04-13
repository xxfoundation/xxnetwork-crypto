////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package ec

import (
	"crypto/rand"
	"github.com/katzenpost/core/crypto/eddsa"
	"reflect"
	"testing"
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
		t.Fatalf("Unmarshalled public key did not match expected resutl." +
			"\n\tExpected: %v" +
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