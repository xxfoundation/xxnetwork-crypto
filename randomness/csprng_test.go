////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"bytes"
	"gitlab.com/xx_network/crypto/hasher"
	"golang.org/x/crypto/sha3"
	"math/big"
	"testing"
)

var (
	i           int      // loop variable
	r           *big.Int // variable for the random value obtained from the PRF
	simulations = 5000000
	s           = []byte("321f485cffb6027f14b7764e8795d6feea5eeeccdc9c08b9487d7b90") // Random value for the PRF
	h           = hasher.BLAKE2.New()
	h2          = hasher.BLAKE3.New()
	seed        = PRF(h, s)
)

// Simple test just to check that the CSPRNG does not generate the same long value
func TestGenerateSecureRandom(t *testing.T) {

	size := 32

	x, _ := GenerateSecureRandom(size)
	y, _ := GenerateSecureRandom(size)
	z, _ := GenerateSecureRandom(size)

	if bytes.Compare(x, y) == 0 {
		t.Errorf("GenerateSecureRandom(): Function output the same value and this should be ~impossible")
	}

	if bytes.Compare(y, z) == 0 {
		t.Errorf("GenerateSecureRandom(): Function output the same value and this should be ~impossible")
	}

	if bytes.Compare(x, z) == 0 {
		t.Errorf("GenerateSecureRandom(): Function output the same value and this should be ~impossible")
	}
}

func TestCalculateModuloBias(t *testing.T) {
	// Test 1: Check w/ a value smaller than RAND_Max
	max224 := big.NewInt(224)

	if CalculateModuloBias(max224, 1).Cmp(max224) != 0 {
		t.Errorf("CalculateModuloBias(): function returned a wrong value in test 1")
	}

	max512 := big.NewInt(512)
	expectedRandLimit := big.NewInt(65024)

	if CalculateModuloBias(max512, 2).Cmp(expectedRandLimit) != 0 {
		t.Errorf("CalculateModuloBias(): function returned a wrong value in test 2")
	}
}

func TestRandInInterval(t *testing.T) {

	zero := big.NewInt(0)
	r = RandInInterval(zero, seed, h2)

	if r.Cmp(zero) != 0 {
		t.Errorf("RandInInterval(): function should have returned 0")
	}

	max := big.NewInt(45)
	r = RandInInterval(max, seed, h2)

	if r.Cmp(zero) == -1 || r.Cmp(max) == 1 {
		t.Errorf("RandInInterval(): function returned values out of range")
	}
}

// Simulate a dice throwing and see the probability distribution
func TestRandInInterval_DiceThrow(t *testing.T) {

	// simulate a dice throw by having 6 possible outcomes
	outcomes := 6
	counter := make([]int, outcomes)

	for i = 0; i < outcomes; i++ {
		counter[i] = 0
	}

	ok := true

	for i = 0; i < simulations; i++ {

		seed = PRF(h, seed)
		r = RandInInterval(big.NewInt(int64(outcomes)), seed, h2)

		switch r.Int64() {
		case 0:
			counter[0]++
		case 1:
			counter[1]++
		case 2:
			counter[2]++
		case 3:
			counter[3]++
		case 4:
			counter[4]++
		case 5:
			counter[5]++
		default:
			ok = false
			break
		}
	}

	total := 0

	for i = 0; i < len(counter); i++ {
		total += counter[i]
	}

	if ok == false || total != simulations {
		t.Errorf("RandInInterval(): Error in the switch statement of the dice throws")
	}

	/*
		p1 := (float64(counter[0])/float64(simulations))*100
		p2 := (float64(counter[1])/float64(simulations))*100
		p3 := (float64(counter[2])/float64(simulations))*100
		p4 := (float64(counter[3])/float64(simulations))*100
		p5 := (float64(counter[4])/float64(simulations))*100
		p6 := (float64(counter[5])/float64(simulations))*100

		fmt.Println("P(1) = ", p1)
		fmt.Println("P(2) = ", p2)
		fmt.Println("P(3) = ", p3)
		fmt.Println("P(4) = ", p4)
		fmt.Println("P(5) = ", p5)
		fmt.Println("P(6) = ", p6)
	*/
}

func TestRandInInterval_CoinFlip(t *testing.T) {

	// Coin Flip only has two outcomes
	outcomes := 2

	counter := make([]int, outcomes)
	ok := true

	for i = 0; i < outcomes; i++ {
		counter[i] = 0
	}

	for i = 0; i < simulations; i++ {

		seed = PRF(h, seed)
		r = RandInInterval(big.NewInt(int64(outcomes)), seed, h2)

		switch r.Int64() {
		case 0:
			counter[0]++
		case 1:
			counter[1]++
		default:
			ok = false
			break
		}
	}

	p0 := (float64(counter[0]) / float64(simulations)) * 100
	p1 := (float64(counter[1]) / float64(simulations)) * 100

	if ok == false {
		t.Errorf("RandInInterval(): Error in the switch statement of the coin flip")
	}

	if (p0 + p1) != float64(100) {
		t.Errorf("RandInInterval(): Error with the coin flip total probabilities")
	}

	//fmt.Println("P(0) = ", p0)
	//fmt.Println("P(1) = ", p1)
}

func TestPRF(t *testing.T) {

	msg := []byte("Super Mario")

	h := sha3.NewLegacyKeccak256()
	h.Write(msg)
	x := h.Sum(nil)

	y := PRF(h, msg)

	if bytes.Compare(x, y) != 0 {
		t.Errorf("PRF(): Function output different values for the same hash input")
	}
}
