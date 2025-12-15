////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"testing"

	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/testkeys"
)

// Tests that the oldRsa package adheres to the GoRsa interface.
func TestGoRsaRetriever_OldRsa(t *testing.T) {
	// Load pre-generated test key
	pemBytes, err := testkeys.LoadTestRSAKeyPem()
	if err != nil {
		t.Fatalf("Failed to load test RSA key PEM: %+v", err)
	}
	pk, err := oldRsa.LoadPrivateKeyFromPem(pemBytes)
	if err != nil {
		t.Fatalf("Failed to parse test RSA key: %+v", err)
	}

	var _ GoRsa = pk.GetPublic()
}
