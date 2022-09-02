////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file.                                                       //
// NOTE: This code is largely copied from golang's crypto/rsa pcakge, so it   //
//       is 3-clause and not 2-clause BSD. Unchanged code (excepting type     //
//       modifications) is noted at the bottom of this file.                  //
////////////////////////////////////////////////////////////////////////////////

// oaep_test.go implements basic testing for broadcast RSA

package multicastRSA

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	xxrsa "gitlab.com/xx_network/crypto/signature/rsa"
)

func TestEncryptDecryptRSA(t *testing.T) {
	test_messages := [][]byte{
		[]byte("Hello"),
		[]byte("World!"),
		[]byte("How"),
		[]byte("Are"),
		[]byte("You"),
		[]byte(""), // Empty test
		[]byte("averylongmessageaverylongmessageaverylongmessageavery"),
		[]byte("This is a short little message to test it."),
	}

	priv, err := xxrsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pub := priv.GetPublic()

	h := sha256.New()
	label := []byte("testing123")
	rng := rand.Reader

	// Encrypt, then decrypt and check each message
	for i := 0; i < len(test_messages); i++ {
		inM := test_messages[i]
		c, err := EncryptOAEP(h, rng, priv, inM, label)
		if err != nil {
			t.Fatalf("'%s': %+v", inM, err)
		}

		m, err := DecryptOAEP(h, pub, c, label)
		if err != nil {
			t.Fatalf("%+v", err)
		}

		if bytes.Compare(inM, m) != 0 {
			t.Errorf("Encrypt/Decrypt Mismatch, in: %v, out: %v",
				inM, m)
		}
	}
}

func TestEncryptRSATooLong(t *testing.T) {
	too_long := []byte("averylongmessageaverylongmessageaverylongkgeavery" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"messageaverngmessage") // will not fit

	priv, err := xxrsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	// pub := priv.GetPublic()

	h := sha256.New()
	label := []byte("testing123")
	rng := rand.Reader

	inM := too_long
	_, err = EncryptOAEP(h, rng, priv, inM, label)
	if err == nil {
		t.Fatalf("Message should have been too long to encrypt!")
	}
}
