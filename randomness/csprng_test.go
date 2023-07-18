////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"bytes"
	"math/big"
	"testing"

	"gitlab.com/xx_network/crypto/hasher"
	"golang.org/x/crypto/sha3"
)

var (
	simulations = 5000000
	s           = []byte("321f485cffb6027f14b7764e8795d6feea5eeeccdc9c08b9487d7b90") // Random value for the PRF
	h           = hasher.BLAKE2.New()
	h2          = hasher.BLAKE3.New()
	seed        = PRF(h, s)
)

// Simple test just to check that GenerateSecureRandom does not generate the
// same long value.
func TestGenerateSecureRandom(t *testing.T) {
	size := 32

	x, _ := GenerateSecureRandom(size)
	y, _ := GenerateSecureRandom(size)
	z, _ := GenerateSecureRandom(size)

	if !bytes.Equal(x, y) {
		t.Errorf("Two randoms are the same.\nx: %X\ny: %X", x, y)
	}
	if !bytes.Equal(y, z) {
		t.Errorf("Two randoms are the same.\ny: %X\nz: %X", y, z)
	}
	if !bytes.Equal(x, z) {
		t.Errorf("Two randoms are the same.\nx: %X\nz: %X", x, z)
	}
}

func TestCalculateModuloBias(t *testing.T) {
	// Test 1: Check w/ a value smaller than RAND_Max
	max224 := big.NewInt(224)

	bias := CalculateModuloBias(max224, 1)
	if bias.Cmp(max224) != 0 {
		t.Errorf("Ints should be the same.\nexpected: %s\nreceived: %s",
			max224, bias)
	}

	max512 := big.NewInt(512)
	expectedRandLimit := big.NewInt(65024)

	bias = CalculateModuloBias(max512, 2)
	if bias.Cmp(expectedRandLimit) != 0 {
		t.Errorf("Ints should be the same.\nexpected: %s\nreceived: %s",
			expectedRandLimit, bias)
	}
}

func TestRandInInterval(t *testing.T) {
	zero := big.NewInt(0)
	r := RandInInterval(zero, seed, h2)

	if r.Cmp(zero) != 0 {
		t.Errorf("RandInInterval: function should have returned 0")
	}

	max := big.NewInt(45)
	r = RandInInterval(max, seed, h2)

	if r.Cmp(zero) == -1 || r.Cmp(max) == 1 {
		t.Errorf("RandInInterval: function returned values out of range")
	}
}

// Simulate a die throwing and see the probability distribution.
func TestRandInInterval_DiceThrow(t *testing.T) {
	// Simulate a die throw by having 6 possible outcomes
	const outcomes = 6
	counter := make([]int, outcomes)
	for i := range counter {
		counter[i] = 0
	}

	var total int
	for i := 0; i < simulations; i++ {
		seed = PRF(h, seed)
		r := RandInInterval(big.NewInt(outcomes), seed, h2)

		i64 := r.Int64()
		if i64 < 0 || i64 >= outcomes {
			t.Fatalf("Int %d outside range of %d to %d", i64, 0, outcomes)
		} else {
			counter[i64]++
			total++
		}
	}

	if total != simulations {
		t.Errorf(
			"Incorrect total.\nexpected: %d\nreceived: %d", total, simulations)
	}
}

func TestRandInInterval_CoinFlip(t *testing.T) {
	// Coin Flip only has two outcomes
	const outcomes = 2
	counter := make([]int, outcomes)
	for i := 0; i < simulations; i++ {

		seed = PRF(h, seed)
		r := RandInInterval(big.NewInt(int64(outcomes)), seed, h2)

		i64 := r.Int64()
		if i64 < 0 || i64 >= outcomes {
			t.Fatalf("Int %d outside range of %d to %d", i64, 0, outcomes)
		} else {
			counter[i64]++
		}
	}

	p0 := (float64(counter[0]) / float64(simulations)) * 100
	p1 := (float64(counter[1]) / float64(simulations)) * 100

	if (p0 + p1) != float64(100) {
		t.Errorf("Error with the coin flip total probabilities."+
			"\nexpected: %f\nreceived: %f", p0+p1, float64(100))
	}
}

func TestPRF(t *testing.T) {
	msg := []byte("Super Mario")

	h := sha3.NewLegacyKeccak256()
	h.Write(msg)
	x := h.Sum(nil)

	y := PRF(h, msg)

	if !bytes.Equal(x, y) {
		t.Errorf("Function output different values for the same hash input.")
	}
}
