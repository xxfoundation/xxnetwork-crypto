package shuffle

import (
	"gitlab.com/xx_network/comms/crypto/hasher"
	"gitlab.com/xx_network/comms/crypto/randomness"
	"testing"
)

var (
	h = hasher.SHA2_224.New()
	//s = []byte("321f485cffb6027f14b7764e8795d6feea5eeeccdc9c08b9487d7b90")
)

// Auxiliary function to compare int arrays
func Equal(l1 []int, l2 []int) bool {

	if len(l1) != len(l2) {
		return false
	}

	for i := 0; i < len(l1); i++ {
		if l1[i] != l2[i] {
			return false
		}
	}

	return true
}

// Test to check if function produces two identical lists with two different seeds
func TestSeededShuffle_Lists(t *testing.T) {

	listSize := 10

	m1 := []byte("Super Mario")
	m2 := []byte("Baltasar")

	seed1 := randomness.PRF(h, m1)
	seed2 := randomness.PRF(h, m2)

	listA := SeededShuffle(listSize, seed1)
	listB := SeededShuffle(listSize, seed2)
	listC := SeededShuffle(listSize, seed2)

	if Equal(listA, listB) {
		t.Errorf("SeededShuffle(): Function output equal lists.")
	}

	if !Equal(listB, listC) {
		t.Errorf("SeededShuffle(): Function output different lists and they should be equal.")
	}
}
