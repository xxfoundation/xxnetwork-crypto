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

// TestRSASmoke signs and verifies a data packet, and reads all the values to
// ensure they match output that was previously computed.
func TestRSASmoke(t *testing.T) {
	expectedHash := []byte{14, 87, 81, 192, 38, 229, 67, 178, 232, 171, 46, 176,
		96, 153, 218, 161, 209, 229, 223, 71, 119, 143, 119, 135, 250, 171, 69,
		205, 241, 47, 227, 168}
	expectedD := []byte{191, 83, 226, 45, 123, 102, 5, 27, 240, 27, 182, 131,
		201, 32, 162, 16, 178, 32, 115, 110, 86, 198, 4, 228, 177, 195, 106, 44,
		21, 255, 56, 71, 56, 228, 154, 225, 198, 31, 61, 167, 105, 90, 204, 67,
		206, 66, 242, 98, 160, 131, 91, 175, 139, 199, 179, 214, 59, 187, 166,
		130, 92, 10, 223, 93, 114, 142, 87, 208, 71, 94, 104, 102, 168, 208, 47,
		200, 235, 56, 2, 75, 98, 234, 52, 66, 100, 60, 104, 213, 78, 99, 17,
		109, 26, 169, 22, 118, 109, 138, 204, 69, 155, 92, 135, 46, 248, 114,
		155, 134, 217, 33, 93, 161, 145, 189, 33, 211, 118, 154, 60, 112, 220,
		13, 1, 206, 22, 105, 198, 65}
	expectedDp := []byte{86, 80, 29, 65, 17, 139, 88, 124, 76, 198, 147, 183,
		136, 1, 206, 242, 195, 61, 10, 45, 254, 120, 69, 105, 57, 179, 128, 164,
		116, 238, 187, 223, 176, 41, 247, 26, 235, 101, 50, 86, 38, 160, 109,
		145, 97, 219, 168, 204, 157, 22, 228, 7, 216, 82, 31, 67, 19, 141, 90,
		126, 78, 200, 149, 185}
	expectedDq := []byte{159, 52, 202, 32, 119, 12, 161, 248, 78, 228, 121, 208,
		38, 188, 81, 167, 254, 148, 41, 127, 214, 107, 83, 27, 92, 128, 42, 243,
		52, 88, 2, 203, 12, 47, 218, 162, 228, 7, 178, 122, 187, 223, 138, 82,
		147, 183, 98, 42, 107, 143, 58, 2, 67, 103, 17, 218, 27, 62, 233,
		177, 243, 22, 193, 137}

	expectedPrimes := [2][]byte{
		{214, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
			39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
			56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
			73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85},
		{233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
			247, 248, 249, 250, 251, 252, 253, 254, 0, 1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
			26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
	}
	expectedSig := []byte{135, 186, 44, 28, 242, 70, 228, 209, 219, 247, 246,
		132, 28, 116, 162, 90, 245, 248, 193, 255, 22, 121, 209, 90, 57, 32,
		193, 83, 241, 49, 223, 16, 239, 185, 249, 125, 199, 99, 198, 151, 178,
		120, 202, 11, 126, 91, 171, 1, 206, 184, 178, 111, 202, 114, 201, 44,
		147, 163, 37, 74, 130, 252, 14, 213, 10, 66, 76, 211, 40, 250, 235, 233,
		250, 226, 43, 150, 59, 85, 154, 255, 212, 229, 240, 162, 248, 217, 88,
		22, 0, 154, 84, 204, 182, 225, 50, 161, 216, 106, 76, 93, 102, 86, 35,
		151, 68, 204, 24, 206, 51, 90, 50, 97, 28, 125, 101, 140, 58, 249, 60,
		83, 44, 157, 141, 191, 192, 237, 136, 20}
	expectedN := []byte{195, 159, 123, 88, 55, 24, 254, 233, 218, 210, 210, 219,
		239, 13, 55, 110, 180, 8, 108, 226, 106, 3, 221, 96, 57, 41, 49, 82,
		141, 228, 86, 230, 148, 97, 78, 92, 140, 224, 87, 244, 183, 161, 179,
		239, 84, 229, 162, 140, 164, 236, 100, 12, 231, 246, 56, 176, 94, 67,
		96, 183, 72, 20, 28, 97, 115, 128, 12, 87, 96, 37, 166, 226, 216, 134,
		237, 9, 220, 99, 158, 140, 43, 123, 123, 41, 133, 142, 152, 249, 2, 181,
		15, 15, 182, 0, 239, 128, 179, 134, 250, 11, 187, 6, 238, 112, 140, 64,
		140, 110, 230, 243, 147, 198, 138, 223, 196, 55, 55, 196, 221, 128, 173,
		98, 159, 98, 171, 120, 201, 157}

	data := []byte("Hello, World")
	opts := NewDefaultOptions()
	hash := opts.Hash.New()
	// NOTE: The Sum interface appends to data, and doesn't
	// produce a clean hash, that's why we remove it from the beginning!
	hashed := hash.Sum(data)[len(data):]

	if !bytes.Equal(hashed, expectedHash) {
		t.Logf("\nData: %v\nHash: %v\n", data, hashed)
		t.Errorf("Unexpected hash value, expected: %v", expectedHash)
	}

	notRand := &CountingReader{count: uint8(0)}

	privateKey, err := GenerateKey(notRand, 1024)
	if err != nil {
		t.Errorf("%+v", err)
	}

	privateKey.Precompute() // Generates Dq/Dp

	publicKey := privateKey.Public().(*PublicKey)
	if !bytes.Equal(publicKey.GetN().Bytes(), expectedN) {
		t.Logf("N: %v", publicKey.GetN().Bytes())
		t.Errorf("Bad N-val, expected: %v", expectedN)
	}

	if !bytes.Equal(privateKey.GetD().Bytes(), expectedD) ||
		!bytes.Equal(privateKey.GetDp().Bytes(), expectedDp) ||
		!bytes.Equal(privateKey.GetDq().Bytes(), expectedDq) {
		t.Errorf("Invalid D-values."+
			"\nexpected:\n\tD:  %X\n\tDp: %x\n\tDq: %X"+
			"\nreceived:\n\tD:  %X\n\tDp: %x\n\tDq: %X",
			expectedD, privateKey.GetD(), expectedDp, privateKey.GetDp(),
			expectedDq, privateKey.GetDp())
	}

	ps := privateKey.GetPrimes()
	for i := 0; i < len(ps); i++ {
		if !bytes.Equal(ps[i].Bytes(), expectedPrimes[i]) {
			t.Logf("Prime %d: %v", i, ps[i].Bytes())
			t.Fatalf("Bad prime value for prime %d", i)
		}
	}

	signature, err := Sign(notRand, privateKey, opts.Hash, hashed, nil)
	if err != nil {
		t.Errorf("%v", err)
	}

	if !bytes.Equal(signature, expectedSig) {
		t.Logf("\nSignature: %v", signature)
		t.Errorf("Bad Signature, expected: %v", expectedSig)
	}

	verification := Verify(publicKey, opts.Hash, hashed, signature, nil)

	if verification != nil {
		t.Errorf("Could not verify signature: %v", verification)
	}
}

// TestIsValidSignature creates a signature off of a signer's key and checks its
// validity using IsValidSignature.
//
// It also creates an arbitrary, invalid byte slice and checks its validity
// against the signer's keys.
//
// It finally creates an arbitrary byte slice of a valid size and checks its
// validity.
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
	validSignature, err :=
		Sign(rand.Reader, serverPrivKey, crypto.SHA256, data, nil)
	if err != nil {
		t.Errorf("Failed to sign public key: %+v", err)
	}

	// Check if the signature is valid
	if !IsValidSignature(serverPubKey, validSignature) {
		t.Errorf("Signature is not at least as long as the signer's public key."+
			"\nSignature:  %d\nPublic key: %d",
			len(validSignature), serverPubKey.Size())
	}

	// Create arbitrary byte slice of invalid size
	incorrectSignature := make([]byte, 512)
	_, err = rand.Read(incorrectSignature)
	if err != nil {
		t.Errorf("Failed to create random number")
	}

	// Test arbitrary slice with server's public key
	if IsValidSignature(serverPubKey, incorrectSignature) {
		t.Errorf("Invalid signature returned valid."+
			"\nsignature:  %d \npublic key: %d",
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
		t.Errorf("Expected valid signature."+
			"\nsignature len:              %d\nsignature's public key len: %d",
			len(matchingSig), serverPubKey.Size())
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
	hashed := blake2b.Sum256(message)
	signature, err :=
		Sign(rand.Reader, serverPrivKey, crypto.BLAKE2b_256, hashed[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(serverPubKey2, crypto.BLAKE2b_256, hashed[:], signature, nil)
	if err != nil {
		t.Fatal(err)
	}
}
