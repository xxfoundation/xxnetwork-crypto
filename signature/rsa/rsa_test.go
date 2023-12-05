////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/blake2b"
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

// TestRSASmoke signs and verifies a datapacket, and reads all the values to
// ensure they match output that was previously computed.
func TestRSASmoke(t *testing.T) {
	expected_hash := []byte{23, 140, 202, 65, 134, 231, 87, 45, 172, 155,
		162, 229, 39, 144, 179, 0, 86, 225, 154, 65, 177, 158, 176, 4,
		76, 67, 157, 4, 91, 80, 2, 227}
	expected_D := []byte{191, 83, 226, 45, 123, 102, 5, 27, 240, 27, 182,
		131, 201, 32, 162, 16, 178, 32, 115, 110, 86, 198, 4, 228, 177,
		195, 106, 44, 21, 255, 56, 71, 56, 228, 154, 225, 198, 31, 61,
		167, 105, 90, 204, 67, 206, 66, 242, 98, 160, 131, 91, 175, 139,
		199, 179, 214, 59, 187, 166, 130, 92, 10, 223, 93, 114, 142, 87,
		208, 71, 94, 104, 102, 168, 208, 47, 200, 235, 56, 2, 75, 98,
		234, 52, 66, 100, 60, 104, 213, 78, 99, 17, 109, 26, 169, 22,
		118, 109, 138, 204, 69, 155, 92, 135, 46, 248, 114, 155, 134,
		217, 33, 93, 161, 145, 189, 33, 211, 118, 154, 60, 112, 220, 13,
		1, 206, 22, 105, 198, 65}
	expected_Dp := []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147,
		183, 136, 1, 206, 242, 195, 61, 10, 45, 254, 120, 69, 105, 57,
		179, 128, 164, 116, 238, 187, 223, 176, 41, 247, 26, 235, 101,
		50, 86, 38, 160, 109, 145, 97, 219, 168, 204, 157, 22, 228, 7,
		216, 82, 31, 67, 19, 141, 90, 126, 78, 200, 149, 185}
	expected_Dq := []byte{159, 52, 202, 32, 119, 12, 161, 248, 78, 228, 121,
		208, 38, 188, 81, 167, 254, 148, 41, 127, 214, 107, 83, 27, 92,
		128, 42, 243, 52, 88, 2, 203, 12, 47, 218, 162, 228, 7, 178,
		122, 187, 223, 138, 82, 147, 183, 98, 42, 107, 143, 58, 2, 67,
		103, 17, 218, 27, 62, 233, 177, 243, 22, 193, 137}

	expected_primes := [2][]byte{
		{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
			35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
			48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
			61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
			74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85},
		{233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243,
			244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
	}
	expected_sig := []byte{98, 58, 170, 225, 75, 40, 92, 163, 34, 153, 49,
		152, 207, 214, 1, 99, 8, 169, 250, 212, 0, 110, 129, 13, 138,
		206, 194, 128, 245, 90, 187, 195, 59, 54, 108, 216, 25, 250,
		249, 61, 58, 174, 78, 207, 138, 223, 212, 42, 194, 5, 234,
		197, 37, 60, 27, 67, 68, 141, 78, 119, 209, 27, 170, 168, 74,
		77, 100, 86, 197, 229, 82, 52, 56, 202, 61, 163, 26, 58, 113,
		200, 189, 116, 169, 65, 166, 193, 93, 38, 218, 237, 246, 247,
		199, 145, 234, 126, 244, 0, 248, 35, 251, 167, 246, 197, 90,
		122, 78, 206, 216, 54, 39, 206, 60, 1, 80, 166, 88, 238, 141, 1,
		30, 190, 245, 135, 5, 132, 8, 47}
	expected_N := []byte{195, 159, 123, 88, 55, 24, 254, 233, 218, 210, 210,
		219, 239, 13, 55, 110, 180, 8, 108, 226, 106, 3, 221, 96, 57,
		41, 49, 82, 141, 228, 86, 230, 148, 97, 78, 92, 140, 224, 87,
		244, 183, 161, 179, 239, 84, 229, 162, 140, 164, 236, 100, 12,
		231, 246, 56, 176, 94, 67, 96, 183, 72, 20, 28, 97, 115, 128,
		12, 87, 96, 37, 166, 226, 216, 134, 237, 9, 220, 99, 158, 140,
		43, 123, 123, 41, 133, 142, 152, 249, 2, 181, 15, 15, 182, 0,
		239, 128, 179, 134, 250, 11, 187, 6, 238, 112, 140, 64, 140,
		110, 230, 243, 147, 198, 138, 223, 196, 55, 55, 196, 221, 128,
		173, 98, 159, 98, 171, 120, 201, 157}

	data := []byte("Hello, World")
	opts := NewDefaultOptions()
	hash := opts.Hash.New()
	hash.Write(data)
	hashed := hash.Sum(nil)

	if !bytes.Equal(hashed, expected_hash) {
		t.Logf("\nData: %v\nHash: %v\n", data, hashed)
		t.Errorf("Unexpected hash value, expected: %v", expected_hash)
	}

	notRand := &CountingReader{count: uint8(0)}

	privateKey, err := GenerateKey(notRand, 1024)
	privateKey.Precompute() // Generates Dq/Dp

	if err != nil {
		t.Errorf("%v", err)
	}
	publicKey := privateKey.Public().(*PublicKey)
	if !bytes.Equal(publicKey.GetN().Bytes(), expected_N) {
		t.Logf("N: %v", publicKey.GetN().Bytes())
		t.Errorf("Bad N-val, expected: %v", expected_N)
	}

	if !bytes.Equal(privateKey.GetD().Bytes(), expected_D) ||
		!bytes.Equal(privateKey.GetDp().Bytes(), expected_Dp) ||
		!bytes.Equal(privateKey.GetDq().Bytes(), expected_Dq) {
		t.Logf("\nPrivateKey D-Vals: \n\t%v \n\t%v \n\t%v",
			privateKey.GetD().Bytes(),
			privateKey.GetDp().Bytes(),
			privateKey.GetDq().Bytes(),
		)
		t.Errorf("Bad D-Values!")
	}

	ps := privateKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if !bytes.Equal(ps[i].Bytes(), expected_primes[i]) {
			t.Logf("Prime %d: %v", i, ps[i].Bytes())
			t.Fatalf("Bad prime value for prime %d", i)
		}
	}

	signature, err := Sign(notRand, privateKey, opts.Hash, hashed, nil)
	if err != nil {
		t.Errorf("%v", err)
	}

	if !bytes.Equal(signature, expected_sig) {
		t.Logf("\nSignature: %v", signature)
		t.Errorf("Bad Signature, expected: %v", expected_sig)
	}

	verification := Verify(publicKey, opts.Hash, hashed, signature, nil)

	if verification != nil {
		t.Errorf("Could not verify signature: %v", verification)
	}
}

// TestIsValidSignature creates a signature off of a signer's key and
// checks its validity using IsValidSignature.
// It also creates an arbitrary, invalid byte slice and checks its validity
// against the signer's keys
// It finally creates an arbitrary byte slice of a valid size and
// checks its validity
func TestIsValidSignature(t *testing.T) {
	// Generate signer's private key and public key
	serverPrivKey, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.GetPublic()

	// Generate client's private and public key
	clientPrivKey, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	clientPubKey := clientPrivKey.GetPublic()

	// Stringer client's public key so it can be signed by the signer
	clientPubKeyStr := string(CreatePublicKeyPem(clientPubKey))

	// Sign the clients  key with the server's key
	h := sha256.New()
	h.Write([]byte(clientPubKeyStr))
	data := h.Sum(nil)
	validSignature, err := Sign(rand.Reader, serverPrivKey, crypto.SHA256,
		data, nil)
	if err != nil {
		t.Errorf("Failed to sign public key: %+v", err)
	}

	// Check if the signature is valid
	if !IsValidSignature(serverPubKey, validSignature) {
		t.Errorf("Failed smoke test! Signature is not at least as "+
			"long as the signer's public key."+
			"\n\tSignature: %+v"+
			"\n\tSigner's public key: %+v", len(validSignature),
			serverPubKey.Size())
	}

	// Create arbitrary byte slice of invalid size
	incorrectSignature := make([]byte, 512)
	_, err = rand.Read(incorrectSignature)
	if err != nil {
		t.Errorf("Failed to create random number")
	}

	// Test arbitrary slice with server's public key
	if IsValidSignature(serverPubKey, incorrectSignature) {
		t.Errorf("Invalid signature returned valid! "+
			"\n\t Signature: %+v "+
			"\n\t Signer's public key: %+v",
			len(incorrectSignature), serverPubKey.Size())
	}

	// Create arbitrary byte slice of valid size
	matchingSig := make([]byte, serverPubKey.Size())
	_, err = rand.Read(incorrectSignature)
	if err != nil {
		t.Errorf("Failed to create random number")
	}

	// Check it against the server's public key
	if !IsValidSignature(serverPubKey, matchingSig) {
		t.Errorf("Expected valid signature!"+
			"\n\t Signature: %+v"+
			"\n\t Signer's public key: %+v", len(matchingSig),
			serverPubKey.Size())
	}
}

func TestRSABytesFromBytes(t *testing.T) {
	serverPrivKey, err := GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	serverPubKey := serverPrivKey.GetPublic()
	serverPubKeyBytes := serverPubKey.Bytes()
	serverPubKey2 := new(PublicKey)
	err = serverPubKey2.FromBytes(serverPubKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	serverPubKey2Bytes := serverPubKey2.Bytes()
	if !bytes.Equal(serverPubKeyBytes, serverPubKey2Bytes) {
		t.Fatal("byte slices don't match")
	}

	message := []byte("fluffy bunny")
	hash, _ := blake2b.New256(nil)
	hash.Write(message)
	hashed := hash.Sum(nil)
	signature, err := Sign(rand.Reader, serverPrivKey, crypto.BLAKE2b_256,
		hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(serverPubKey2, crypto.BLAKE2b_256, hashed[:], signature,
		nil)
	if err != nil {
		t.Fatal(err)
	}
}
