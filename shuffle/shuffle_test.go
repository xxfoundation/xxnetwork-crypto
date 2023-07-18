////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package shuffle

import (
	"reflect"
	"testing"

	"gitlab.com/xx_network/crypto/hasher"
	"gitlab.com/xx_network/crypto/randomness"
)

var h = hasher.SHA2_224.New()

// Test to check if function produces two identical lists with two different
// seeds.
func TestSeededShuffle_Lists(t *testing.T) {
	listSize := 10

	m1 := []byte("Super Mario")
	m2 := []byte("Baltasar")

	seed1 := randomness.PRF(h, m1)
	seed2 := randomness.PRF(h, m2)

	listA := SeededShuffle(listSize, seed1)
	listB := SeededShuffle(listSize, seed2)
	listC := SeededShuffle(listSize, seed2)

	if reflect.DeepEqual(listA, listB) {
		t.Errorf("Two different lists are equal.\nA: %d\nB: %d", listA, listB)
	}

	if !reflect.DeepEqual(listB, listC) {
		t.Errorf("Two of the same list are not equal.\nB: %d\nC: %d",
			listB, listC)
	}
}
