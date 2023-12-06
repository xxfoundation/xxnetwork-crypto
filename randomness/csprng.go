////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"crypto/rand"
	"hash"
	"math/big"
)

// GenerateSecureRandom receives the number of desired randomness bytes and returns a slice of that size from Crypto.Rand
func GenerateSecureRandom(keySize int) ([]byte, error) {

	k := make([]byte, keySize)
	_, err := rand.Read(k)

	if err != nil {
		return nil, err
	}

	return k, nil
}

// To remove modulo bias, we must calculate RAND_MAX - (RAND_MAX % N)
// Since we use a PRF that outputs a specific number of bytes (requiredBytes)
// RAND_MAX = ((2**(8*requiredBytes)) - 1)
// N = maxValue
// CalculateModuloBias returns those two values and returns the upper bound to avoid modulo bias
func CalculateModuloBias(maxValue *big.Int, requiredBytes int) *big.Int {

	var (
		zero = big.NewInt(0)
		one  = big.NewInt(1)
		two  = big.NewInt(2)
	)

	if maxValue.Cmp(zero) == 0 {
		return zero
	}

	// Convert the number of required bytes to bits to calculate the max PRF possible value (2**b) - 1
	nBits := big.NewInt(int64(8 * requiredBytes))

	// randMax is the max possible number that the PRF can generate within its byte output
	randMax := big.NewInt(0).Exp(two, nBits, nil)
	randMax.Sub(randMax, one)

	randExcess := new(big.Int)
	randExcess.Mod(randMax, maxValue)
	//randExcess.Add(randExcess, one)

	// randLimit is the max value that the RNG can generate. (randLimit = randMax - randExcess)
	randLimit := big.NewInt(0).Sub(randMax, randExcess)

	return randLimit
}

// RandInInterval receives a seed and returns a random value (using a PRF) between [0, max-1]
func RandInInterval(max *big.Int, seed []byte, h hash.Hash) *big.Int {

	// BitLen returns an int with the length of the absolute value of max in bits
	maxBitLength := max.BitLen()

	// If max == 0, the BitLen function returns 0
	if maxBitLength == 0 {
		return big.NewInt(0)
	}

	requiredBytes := (maxBitLength + 7) / 8 // Convert the max bit length to byte
	totalSpace := 3 * requiredBytes         // Increase the random search space

	randomByteValue := make([]byte, totalSpace) // Variable allocation for the random value (in byte)
	randomIntValue := big.NewInt(0)             // Variable allocation for the random value (in big.Int)

	// Calculate randomLimit, which sets the upper bound to ensure no modulo bias comes from the PRF
	randomLimit := CalculateModuloBias(max, totalSpace)

	r := seed

	for {

		r = PRF(h, r) // Call the PRF to generate a random stream from the seed

		copy(randomByteValue, r[0:totalSpace]) // Copy just the necessary bytes

		randomIntValue.SetBytes(randomByteValue) // convert the randomByteValue to Big.Int

		// Check if obtained random value is smaller than randomLimit
		if randomIntValue.Cmp(randomLimit) < 0 {
			return randomIntValue.Mod(randomIntValue, max)
		}
	}
}

// PRF is a pseudorandom function
func PRF(h hash.Hash, seed []byte) []byte {
	h.Reset()
	h.Write(seed)
	return h.Sum(nil)
}
