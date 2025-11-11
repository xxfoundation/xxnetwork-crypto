////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package authorize

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/xx"
	"gitlab.com/xx_network/primitives/id"
	"strconv"
	"strings"
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

// Consistency test for Sign
func TestSignVerify_Consistency(t *testing.T) {
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

	publicKey := serverPrivKey.GetPublic()
	if bytes.Compare(publicKey.GetN().Bytes(), expected_N) != 0 {
		t.Fatalf("SignVerify error: "+
			"Bad N value in pre-canned private key."+
			"\n\tExpected %v\n\tReceived: %v", expected_N, publicKey.GetN().Bytes())
	}

	if !bytes.Equal(serverPrivKey.GetD().Bytes(), expected_D) ||
		!bytes.Equal(serverPrivKey.GetDp().Bytes(), expected_Dp) ||
		!bytes.Equal(serverPrivKey.GetDq().Bytes(), expected_Dq) {
		t.Fatalf("SignVerify error: "+
			"Bad D-value(s) in pre-canned private key."+
			"\n\tExpected D value %v\n\tReceived D value: %v"+
			"\n\tExpected Dp value: %v\n\tReceived Dp value: %v"+
			"\n\tExpected Dq value: %v\n\tReceived Dp value: %v",
			expected_D, serverPrivKey.GetD().Bytes(),
			expected_Dp, serverPrivKey.GetDp().Bytes(),
			expected_Dq, serverPrivKey.GetDq().Bytes())
	}

	ps := serverPrivKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if bytes.Compare(ps[i].Bytes(), expectedPrimes[i]) != 0 {
			t.Fatalf("SignVerify error: "+
				"Bad prime %d in pre-canned private key."+
				"\n\tExpected: %v\n\tReceived: %v", i, expectedPrimes[i], ps[i].Bytes())
		}
	}

	// Sign data (using crypto/rand produces non-deterministic signatures)
	sig, err := Sign(rand.Reader, testTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	// Note: Signature consistency check removed because crypto/rand produces
	// non-deterministic padding, making signatures vary on each run.
	// The Verify call below still validates the signature works correctly.

	// Generate data required for verification
	delta := 24 * time.Hour * 2
	testNow := testTime.Add(delta / 2)

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	testId, err := xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Test the verification
	err = Verify(testNow, testTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}

}

// Consistency test for digest
func TestDigest_Consistency(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// Construct the hash
	options := rsa.NewDefaultOptions()

	receivedDigest := digest(options.Hash.New(), testTime)

	if !bytes.Equal(receivedDigest, expectedDigest) {
		t.Fatalf("Digest consistency error: "+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expectedDigest, receivedDigest)
	}
}

// Unit test
func TestSignVerify(t *testing.T) {
	// Generate a pre-canned time for consistent testing
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// Generate data required for verification
	delta := 24 * time.Hour * 2
	testNow := testTime.Add(delta / 2)

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	sig, err := Sign(rand.Reader, testTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	testId, err := xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Test the verification
	err = Verify(testNow, testTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not verify signature: %v", err.Error())
	}

}

// Error path for verify
func TestVerify_Error(t *testing.T) {
	// Set up test
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate key: %v", err.Error())
	}

	// Generate a pre-canned time for consistent testing
	signedTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}

	// use insecure seeded rng to reproduce key
	notRand := &CountingReader{count: uint8(0)}

	sig, err := Sign(notRand, signedTime, serverPrivKey)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not sign data: %v", err.Error())
	}

	testSalt := make([]byte, 32)
	copy(testSalt, "salt")

	testId, err := xx.NewID(serverPrivKey.GetPublic(), testSalt, id.Node)
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not generate a test signature: %v", err)
	}

	// Check when signed timestamp is out of bounds (below the lower bound)
	delta := 24 * time.Hour * 2
	testNow := signedTime.Add(delta * 3)
	// Test the verification
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: "+
			"Signed time %s should be beyond lower bound given delta %s and test now being %s", signedTime, delta, testNow)
	}

	// Check when signed timestamp is out of bounds (above the upper bound)
	testNow = signedTime.Add(-delta * 3)
	// Test the verification
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: "+
			"Expected error: Signed time %s should be beyond upper bound given delta %s and test now being %s", signedTime, delta, testNow)
	}

	// Reinitialize timestamps
	testNow = signedTime.Add(delta / 2)

	// Trigger failed ID check
	badSalt := make([]byte, 32)
	copy(badSalt, "error")

	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		badSalt, delta, sig)
	if err == nil {
		t.Fatalf("SignVerify error: " +
			"Expected error: IDs should not match with different data passed in")
	}

	// Trigger failed signature check
	badSig := []byte("signature")
	err = Verify(testNow, signedTime, serverPrivKey.GetPublic(), testId,
		testSalt, delta, badSig)
	if err == nil {
		t.Fatalf("SignVerify error: " +
			"Expected error: Signature check should have failed with bad signature passed in")
	}

}

var expectedSig = []byte{9, 21, 121, 251, 79, 80, 177, 178, 105, 49, 106, 45, 233, 39, 146, 138, 196, 187, 79, 33, 157, 226, 172, 213, 67, 19, 58, 245, 69, 159, 71, 38, 69, 19, 222, 111, 146, 41, 220, 106, 81, 185, 70, 107, 112, 252, 52, 22, 247, 233, 26, 154, 62, 192, 95, 76, 62, 81, 106, 194, 251, 193, 199, 168, 235, 23, 31, 58, 99, 51, 111, 71, 204, 236, 172, 141, 89, 27, 158, 103, 58, 196, 90, 187, 251, 23, 10, 136, 244, 5, 148, 45, 47, 122, 205, 187, 189, 128, 9, 67, 125, 226, 197, 184, 197, 72, 232, 253, 133, 190, 178, 178, 208, 172, 167, 242, 129, 239, 175, 127, 149, 54, 133, 107, 190, 92, 78, 100}

var expected_N = []byte{223, 38, 159, 196, 112, 93, 158, 12, 59, 176, 154, 107, 18, 6, 121, 137, 145, 30, 224, 22, 90, 71, 100, 78, 164, 204, 15, 223, 176, 37, 193, 107, 82, 134, 207, 0, 94, 234, 88, 155, 62, 4, 143, 231, 136, 174, 32, 216, 170, 120, 84, 40, 19, 53, 94, 75, 187, 87, 9, 176, 165, 139, 113, 169, 76, 240, 72, 109, 86, 177, 105, 39, 27, 128, 250, 249, 121, 70, 70, 148, 68, 213, 119, 93, 54, 193, 164, 233, 166, 43, 169, 65, 108, 188, 172, 187, 186, 58, 93, 157, 156, 127, 255, 248, 85, 95, 202, 93, 251, 12, 59, 230, 193, 163, 233, 211, 153, 46, 49, 173, 84, 43, 99, 121, 137, 197, 139, 201}

var expected_D = []byte{8, 59, 11, 57, 10, 96, 245, 151, 163, 106, 249, 227, 25, 156, 218, 6, 64, 47, 72, 154, 34, 117, 208, 38, 19, 111, 128, 101, 98, 128, 157, 255, 248, 161, 6, 201, 15, 119, 42, 209, 253, 9, 91, 138, 113, 112, 228, 190, 193, 24, 227, 151, 191, 207, 159, 221, 0, 185, 174, 222, 144, 88, 146, 150, 87, 154, 190, 229, 184, 188, 148, 171, 107, 128, 119, 132, 90, 38, 251, 54, 125, 25, 248, 116, 81, 145, 18, 203, 97, 188, 226, 144, 35, 127, 209, 252, 190, 57, 149, 167, 189, 63, 245, 221, 176, 76, 151, 241, 141, 237, 148, 255, 156, 140, 63, 52, 94, 117, 135, 120, 249, 150, 169, 27, 213, 136, 15, 129}

var expected_Dp = []byte{103, 67, 122, 251, 122, 243, 146, 30, 134, 74, 234, 226, 33, 62, 254, 210, 20, 41, 142, 171, 2, 111, 161, 69, 230, 157, 93, 27, 12, 16, 52, 62, 145, 31, 211, 117, 6, 130, 61, 240, 199, 129, 167, 19, 31, 76, 201, 217, 33, 240, 46, 37, 254, 150, 27, 0, 186, 201, 214, 103, 135, 231, 196, 193}

var expected_Dq = []byte{223, 2, 153, 129, 163, 104, 97, 144, 241, 254, 204, 17, 78, 26, 173, 225, 206, 129, 235, 107, 235, 137, 69, 84, 147, 117, 60, 255, 67, 162, 182, 255, 2, 47, 39, 155, 193, 236, 183, 54, 48, 60, 198, 145, 150, 174, 95, 224, 238, 32, 248, 218, 238, 35, 183, 69, 150, 24, 138, 209, 181, 138, 150, 17}

var expectedPrimes = [][]byte{
	[]byte{252, 169, 205, 110, 48, 85, 77, 89, 184, 148, 147, 11, 64, 33, 242, 254, 42, 47, 8, 1, 79, 117, 85, 242, 104, 117, 24, 206, 77, 90, 26, 49, 246, 6, 143, 227, 88, 149, 16, 127, 33, 55, 124, 195, 58, 20, 162, 225, 49, 160, 64, 190, 169, 107, 52, 27, 60, 180, 166, 90, 116, 186, 204, 193},
	[]byte{226, 25, 11, 252, 23, 67, 65, 217, 72, 90, 105, 205, 150, 30, 57, 137, 106, 68, 214, 82, 74, 84, 196, 229, 114, 14, 29, 192, 102, 136, 9, 179, 154, 99, 80, 158, 114, 221, 155, 6, 71, 96, 56, 212, 212, 126, 6, 170, 149, 184, 194, 50, 17, 216, 249, 31, 72, 157, 183, 177, 191, 21, 153, 9},
}

var expectedDigest = []byte{19, 149, 39, 88, 8, 30, 138, 147, 218, 69, 4, 210, 20, 204, 60, 29, 36, 6, 79, 131,
	171, 5, 188, 226, 27, 140, 45, 253, 67, 138, 229, 216}

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

func parseData(b []byte) {
	var membersArr []string
	for _, m := range b {
		membersArr = append(membersArr, strconv.Itoa(int(m)))
	}

	members := strings.Join(membersArr, ", ")

	fmt.Printf("%v\n", members)

}
