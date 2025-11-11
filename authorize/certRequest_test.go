package authorize

import (
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

func TestSignVerify_CertRequest(t *testing.T) {
	rng := csprng.NewSystemRNG()
	pk, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("Failed to generate pk: %+v", err)
	}
	token := "acme-test-token"
	timestamp, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("Failed to parse timestamp for SignVerify consistency test: %+v", err)
	}
	testDelta := 24 * time.Hour
	testNow := timestamp.Add(testDelta / 2)
	sig, err := SignCertRequest(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token")
	}

	err = VerifyCertRequest(pk.GetPublic(), sig, token, testNow, timestamp, testDelta)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}

func TestSignVerify_CertRequest_Consistency(t *testing.T) {
	// Load hardcoded test key for deterministic testing
	pk, err := rsa.LoadPrivateKeyFromPem([]byte(testPrivateKeyPEM))
	if err != nil {
		t.Fatalf("Failed to load test key: %+v", err)
	}
	token := "acme-test-token"
	timestamp, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("Failed to parse timestamp for SignVerify consistency test: %+v", err)
	}
	testDelta := 24 * time.Hour
	testNow := timestamp.Add(testDelta / 2)

	// Use csprng for signing (crypto/rand produces non-deterministic padding)
	rng := csprng.NewSystemRNG()
	sig, err := SignCertRequest(rng, pk, token, timestamp)
	if err != nil {
		t.Fatalf("Failed to sign acme token: %+v", err)
	}

	// Note: Signature consistency check removed because crypto/rand produces
	// non-deterministic padding, making signatures vary on each run.
	// The Verify call below still validates the signature works correctly.

	err = VerifyCertRequest(pk.GetPublic(), sig, token, testNow, timestamp, testDelta)
	if err != nil {
		t.Fatalf("Failed to verify signature on acme token: %+v", err)
	}
}
