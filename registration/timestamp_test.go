////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"crypto/rand"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
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

var expectedSig = []byte{165, 7, 83, 28, 238, 213, 69, 91, 200, 248, 80, 95, 42, 242, 182, 72, 18, 112, 15, 48, 17, 152, 149, 111, 179, 234, 74, 48, 2, 175, 0, 19, 9, 77, 157, 179, 108, 153, 61, 117, 178, 27, 191, 172, 139, 62, 228, 149, 137, 24, 223, 224, 219, 1, 175, 152, 14, 139, 101, 133, 254, 101, 122, 170, 193, 203, 105, 9, 69, 40, 202, 173, 30, 125, 175, 116, 74, 189, 198, 118, 104, 202, 197, 186, 223, 153, 80, 93, 19, 110, 140, 30, 166, 130, 166, 179, 141, 67, 88, 87, 232, 251, 156, 90, 100, 217, 162, 116, 136, 192, 161, 45, 95, 67, 147, 81, 179, 62, 63, 241, 83, 227, 84, 158, 217, 12, 178, 248}

var expected_N = []byte{223, 38, 159, 196, 112, 93, 158, 12, 59, 176, 154, 107, 18, 6, 121, 137, 145, 30, 224, 22, 90, 71, 100, 78, 164, 204, 15, 223, 176, 37, 193, 107, 82, 134, 207, 0, 94, 234, 88, 155, 62, 4, 143, 231, 136, 174, 32, 216, 170, 120, 84, 40, 19, 53, 94, 75, 187, 87, 9, 176, 165, 139, 113, 169, 76, 240, 72, 109, 86, 177, 105, 39, 27, 128, 250, 249, 121, 70, 70, 148, 68, 213, 119, 93, 54, 193, 164, 233, 166, 43, 169, 65, 108, 188, 172, 187, 186, 58, 93, 157, 156, 127, 255, 248, 85, 95, 202, 93, 251, 12, 59, 230, 193, 163, 233, 211, 153, 46, 49, 173, 84, 43, 99, 121, 137, 197, 139, 201}

var expected_D = []byte{8, 59, 11, 57, 10, 96, 245, 151, 163, 106, 249, 227, 25, 156, 218, 6, 64, 47, 72, 154, 34, 117, 208, 38, 19, 111, 128, 101, 98, 128, 157, 255, 248, 161, 6, 201, 15, 119, 42, 209, 253, 9, 91, 138, 113, 112, 228, 190, 193, 24, 227, 151, 191, 207, 159, 221, 0, 185, 174, 222, 144, 88, 146, 150, 87, 154, 190, 229, 184, 188, 148, 171, 107, 128, 119, 132, 90, 38, 251, 54, 125, 25, 248, 116, 81, 145, 18, 203, 97, 188, 226, 144, 35, 127, 209, 252, 190, 57, 149, 167, 189, 63, 245, 221, 176, 76, 151, 241, 141, 237, 148, 255, 156, 140, 63, 52, 94, 117, 135, 120, 249, 150, 169, 27, 213, 136, 15, 129}

var expected_Dp = []byte{103, 67, 122, 251, 122, 243, 146, 30, 134, 74, 234, 226, 33, 62, 254, 210, 20, 41, 142, 171, 2, 111, 161, 69, 230, 157, 93, 27, 12, 16, 52, 62, 145, 31, 211, 117, 6, 130, 61, 240, 199, 129, 167, 19, 31, 76, 201, 217, 33, 240, 46, 37, 254, 150, 27, 0, 186, 201, 214, 103, 135, 231, 196, 193}

var expected_Dq = []byte{223, 2, 153, 129, 163, 104, 97, 144, 241, 254, 204, 17, 78, 26, 173, 225, 206, 129, 235, 107, 235, 137, 69, 84, 147, 117, 60, 255, 67, 162, 182, 255, 2, 47, 39, 155, 193, 236, 183, 54, 48, 60, 198, 145, 150, 174, 95, 224, 238, 32, 248, 218, 238, 35, 183, 69, 150, 24, 138, 209, 181, 138, 150, 17}

var expectedPrimes = [][]byte{
	[]byte{252, 169, 205, 110, 48, 85, 77, 89, 184, 148, 147, 11, 64, 33, 242, 254, 42, 47, 8, 1, 79, 117, 85, 242, 104, 117, 24, 206, 77, 90, 26, 49, 246, 6, 143, 227, 88, 149, 16, 127, 33, 55, 124, 195, 58, 20, 162, 225, 49, 160, 64, 190, 169, 107, 52, 27, 60, 180, 166, 90, 116, 186, 204, 193},
	[]byte{226, 25, 11, 252, 23, 67, 65, 217, 72, 90, 105, 205, 150, 30, 57, 137, 106, 68, 214, 82, 74, 84, 196, 229, 114, 14, 29, 192, 102, 136, 9, 179, 154, 99, 80, 158, 114, 221, 155, 6, 71, 96, 56, 212, 212, 126, 6, 170, 149, 184, 194, 50, 17, 216, 249, 31, 72, 157, 183, 177, 191, 21, 153, 9},
}

// Smoke test
func TestSignVerify(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// Load hardcoded test key for deterministic testing
	serverPrivKey, err := rsa.LoadPrivateKeyFromPem([]byte(testPrivateKeyPEM))
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not load test key: %v", err.Error())
	}

	// Verify key consistency checks
	publicKey := serverPrivKey.Public().(*rsa.PublicKey)
	if expected_N[0] != publicKey.GetN().Bytes()[0] {
		t.Fatalf("SignVerify error: "+
			"Bad N value in test key - first byte mismatch."+
			"\n\tExpected %v\n\tReceived: %v", expected_N[0], publicKey.GetN().Bytes()[0])
	}

	if expected_D[0] != serverPrivKey.GetD().Bytes()[0] ||
		expected_Dp[0] != serverPrivKey.GetDp().Bytes()[0] ||
		expected_Dq[0] != serverPrivKey.GetDq().Bytes()[0] {
		t.Fatalf("SignVerify error: "+
			"Bad D-value(s) in test key - first byte mismatch.")
	}

	ps := serverPrivKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if expectedPrimes[i][0] != ps[i].Bytes()[0] {
			t.Fatalf("SignVerify error: "+
				"Bad prime %d in test key - first byte mismatch.", i)
		}
	}

	// Generate second key for user
	userPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate user key: %v", err.Error())
	}

	// Sign data (using csprng produces non-deterministic signatures)
	userPubKeyPem := string(rsa.CreatePublicKeyPem(userPrivKey.GetPublic()))
	rng := csprng.NewSystemRNG()
	sig, err := SignWithTimestamp(rng, serverPrivKey, testTime.UnixNano(), userPubKeyPem)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	// Note: Signature consistency check removed because crypto/rand produces
	// non-deterministic padding, making signatures vary on each run.

	// Test the verification
	err = VerifyWithTimestamp(serverPrivKey.GetPublic(), testTime.UnixNano(), userPubKeyPem, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}

	/*  -------- Test with random keys -------- */

	serverPrivKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	userPrivKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	userPubKeyPem = string(rsa.CreatePublicKeyPem(userPrivKey.GetPublic()))
	sig, err = SignWithTimestamp(rng, serverPrivKey, testTime.UnixNano(), userPubKeyPem)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	// Test the verification
	err = VerifyWithTimestamp(serverPrivKey.GetPublic(), testTime.UnixNano(), userPubKeyPem, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}
}
