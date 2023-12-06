////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"testing"

	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
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

// Tests that the oldRsa package adheres to the GoRsa interface.
func TestGoRsaRetriever_OldRsa(t *testing.T) {
	rng := &CountingReader{}
	pk, err := oldRsa.GenerateKey(rng, 1024)
	if err != nil {
		t.Fatalf("Failed to generate key: %+v", err)
	}

	var _ GoRsa = pk.GetPublic()
}
