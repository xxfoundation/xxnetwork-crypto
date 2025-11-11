////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"testing"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
)

// Hardcoded test RSA private key (1024-bit) for deterministic testing
const testPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDfJp/EcF2eDDuwmmsSBnmJkR7gFlpHZE6kzA/fsCXBa1KGzwBe
6libPgSP54iuINiqeFQoEzVeS7tXCbCli3GpTPBIbVaxaScbgPr5eUZGlETVd102
waTppiupQWy8rLu6Ol2dnH//+FVfyl37DDvmwaPp05kuMa1UK2N5icWLyQIDAQAB
AoGACDsLOQpg9ZejavnjGZzaBkAvSJoiddAmE2+AZWKAnf/4oQbJD3cq0f0JW4px
cOS+wRjjl7/Pn90Aua7ekFiSlleavuW4vJSra4B3hFom+zZ9Gfh0UZESy2G84pAj
f9H8vjmVp70/9d2wTJfxje2U/5yMPzRedYd4+ZapG9WID4ECQQD8qc1uMFVNWbiU
kwtAIfL+Ki8IAU91VfJodRjOTVoaMfYGj+NYlRB/ITd8wzoUouExoEC+qWs0Gzy0
plp0uszBAkEA4hkL/BdDQdlIWmnNlh45iWpE1lJKVMTlcg4dwGaICbOaY1Cect2b
BkdgONTUfgaqlbjCMhHY+R9InbexvxWZCQJAZ0N6+3rzkh6GSuriIT7+0hQpjqsC
b6FF5p1dGwwQND6RH9N1BoI98MeBpxMfTMnZIfAuJf6WGwC6ydZnh+fEwQJBAN8C
mYGjaGGQ8f7MEU4areHOgetr64lFVJN1PP9Dorb/Ai8nm8HstzYwPMaRlq5f4O4g
+NruI7dFlhiK0bWKlhECQG9TwomdpyQWlCCrE017CdnFZIWqGe07CdGRxwsWNH4M
0GIxWGT8/CVXDaPDWcmwnCKZWp1mIhttuZWbIu+14vM=
-----END RSA PRIVATE KEY-----`

// Tests that the newRsa package adheres to the GoRsa interface.
func TestGoRsaRetriever_NewRsa(t *testing.T) {
	pk, err := GetScheme().UnmarshalPrivateKeyPEM([]byte(testPrivateKeyPEM))
	if err != nil {
		t.Fatalf("Failed to unmarshal test key: %v", err)
	}

	var _ xx.GoRsa = pk.Public()
}

// Tests NewID.
func TestNewID(t *testing.T) {
	pk, err := GetScheme().UnmarshalPrivateKeyPEM([]byte(testPrivateKeyPEM))
	if err != nil {
		t.Fatalf("Failed to unmarshal test key: %v", err)
	}

	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		salt[i] = byte(i)
	}
	nid, err := xx.NewID(pk.Public(), salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(nid) != id.ArrIDLen {
		t.Errorf("wrong ID length: %d", len(nid))
	}
	if nid[len(nid)-1] != 1 {
		t.Errorf("wrong type: %d", nid[len(nid)-1])
	}

	// Send bad type
	_, err = xx.NewID(pk.Public(), salt, 7)
	if err == nil {
		t.Errorf("Should have failed with bad type!")
	}

	// Send bad salt
	_, err = xx.NewID(pk.Public(), salt[0:4], 7)
	if err == nil {
		t.Errorf("Should have failed with bad salt!")
	}

	// Check ideal usage with our RNG
	rng2 := csprng.NewSystemRNG()
	pk, err = GetScheme().Generate(rng2, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt, err = csprng.Generate(32, rng2)
	if err != nil {
		t.Errorf(err.Error())
	}
	nid, err = xx.NewID(pk.Public(), salt, id.Gateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
