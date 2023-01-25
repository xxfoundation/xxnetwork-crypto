////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/crypto/csprng"
	oldRsa "gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"strconv"
	"strings"
	"testing"
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

// Tests that the newRsa package adheres to the GoRsa interface.
func TestGoRsaRetriever_NewRsa(t *testing.T) {
	rng := &CountingReader{count: 1}
	pk, err := rsa.GetScheme().Generate(rng, 1024)
	if err != nil {
		t.Errorf(err.Error())
	}

	var _ GoRsa = pk.Public()
}

// Tests NewID.
func TestNewID(t *testing.T) {
	// use insecure seeded rng to reproduce key

	rng := &CountingReader{count: 1}
	pk, err := rsa.GetScheme().Generate(rng, 1024)

	if err != nil {
		t.Errorf(err.Error())
	}
	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		salt[i] = byte(i)
	}
	nid, err := NewID(pk.Public(), salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(nid) != id.ArrIDLen {
		t.Errorf("wrong ID length: %d", len(nid))
	}
	if nid[len(nid)-1] != 1 {
		t.Errorf("wrong type: %d", nid[len(nid)-1])
	}

	expectedID1 := id.NewIdFromBytes([]byte{219, 230, 150, 81, 207, 49, 51, 222, 66, 199, 131, 254, 182, 254, 241, 109, 209, 183, 134, 83, 35, 142, 235, 195, 156, 173, 194, 128, 46, 10, 2, 51, 1}, t)

	if !reflect.DeepEqual(expectedID1, nid) {
		strs := make([]string, 0)
		for _, n := range nid {
			strs = append(strs, strconv.Itoa(int(n)))
		}

		t.Logf("%s", strings.Join(strs, ", "))

		t.Errorf("Received ID did not match expected: "+
			"Expected: %s, Received: %s", expectedID1, nid)
	}

	// Send bad type
	_, err = NewID(pk.Public(), salt, 7)
	if err == nil {
		t.Errorf("Should have failed with bad type!")
	}

	// Send back salt
	_, err = NewID(pk.Public(), salt[0:4], 7)
	if err == nil {
		t.Errorf("Should have failed with bad salt!")
	}

	// Check ideal usage with our RNG
	rng2 := csprng.NewSystemRNG()
	pk, err = rsa.GetScheme().Generate(rng2, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt, err = csprng.Generate(32, rng)
	if err != nil {
		t.Errorf(err.Error())
	}
	nid, err = NewID(pk.Public(), salt, id.Gateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
