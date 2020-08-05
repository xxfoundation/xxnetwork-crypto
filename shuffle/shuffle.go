package shuffle

import (
	"gitlab.com/xx_network/comms/crypto/hasher"
	"gitlab.com/xx_network/comms/crypto/randomness"
	"math/big"
)

func CreateList(size int) []int {
	list := make([]int, size)

	// Create List
	for i := 0; i < size; i++ {
		list[i] = i
	}
	return list
}

// SeededShuffle performs a deterministic Fisher-Yates Shuffle given a list size and a random seed
func SeededShuffle(size int, seed []byte) []int {

	var (
		j   int
		max *big.Int
		// Blake2 is used to hash the seed when shuffling each position
		h = hasher.BLAKE2.New()
		// Blake3 is used as a PRF to obtain verifiable random numbers
		h2 = hasher.BLAKE3.New()
		s  = seed
	)

	// Create a new list
	list := CreateList(size)

	for i := size - 1; i > 0; i-- {

		// update the new value of max to current list index
		max = big.NewInt(int64(i + 1))

		// generate a (verifiable) random number between [0, max), convert it to int, and exchange list[j] and list [i]
		j = int(randomness.RandInInterval(max, s, h2).Int64())
		list[j], list[i] = list[i], list[j]

		// Hash the seed value so that next iteration of the loop does not return the same value
		s = randomness.PRF(h, s)
	}
	return list
}
