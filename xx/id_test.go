////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	// use insecure seeded rng to reproduce key
	rng := rand.New(rand.NewSource(42))
	rng.Seed(42)
	pk, err := rsa.GenerateKey(rng, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		salt[i] = byte(i)
	}
	nid, err := NewID(pk.GetPublic(), salt, 1)
	if err != nil {
		t.Errorf(err.Error())
	}
	if len(nid) != id.ArrIDLen {
		t.Errorf("wrong ID length: %d", len(nid))
	}
	if nid[len(nid)-1] != 1 {
		t.Errorf("wrong type: %d", nid[len(nid)-1])
	}

	// rsa key generation has two possible outputs to stop use of its
	// deterministic nature so we check both possible outputs and use
	// its deterministic nature
	expectedID1 := id.NewIdFromBytes([]byte{138, 208, 78, 130, 167, 86, 175, 13, 39,
		241, 229, 186, 201, 235, 149, 13, 201, 136, 196, 157, 41, 149, 93, 250, 127,
		251, 203, 111, 57, 168, 66, 4, 1}, t)

	expectedID2 := id.NewIdFromBytes([]byte{138, 208, 78, 130, 167, 86, 175, 13, 39, 241,
		229, 186, 201, 235, 149, 13, 201, 136, 196, 157, 41, 149, 93, 250, 127, 251, 203,
		111, 57, 168, 66, 4, 1}, t)

	if !reflect.DeepEqual(expectedID1, nid) && !reflect.DeepEqual(expectedID2, nid) {
		strs := make([]string, 0)
		for _, n := range nid {
			strs = append(strs, strconv.Itoa(int(n)))
		}

		t.Logf("%s", strings.Join(strs, ", "))

		t.Errorf("Received ID did not match expected: "+
			"Expected: %s or %s, Received: %s", expectedID1, expectedID2, nid)
	}

	// Send bad type
	_, err = NewID(pk.GetPublic(), salt, 7)
	if err == nil {
		t.Errorf("Should have failed with bad type!")
	}

	// Send back salt
	_, err = NewID(pk.GetPublic(), salt[0:4], 7)
	if err == nil {
		t.Errorf("Should have failed with bad salt!")
	}

	// Check ideal usage with our RNG
	rng2 := csprng.NewSystemRNG()
	pk, err = rsa.GenerateKey(rng2, 4096)
	if err != nil {
		t.Errorf(err.Error())
	}
	salt, err = csprng.Generate(32, rng)
	if err != nil {
		t.Errorf(err.Error())
	}
	nid, err = NewID(pk.GetPublic(), salt, id.Gateway)
	if err != nil {
		t.Errorf(err.Error())
	}
}
