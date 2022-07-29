////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"math/rand"
	"testing"
)

//TestReadRangeSmoke will check that the results of ReadRangeUint32 gets random
// numbers from inside the right range. It verifies
func TestReadRangeSmoke(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 10; i++ {
		for j := 0; j < 30; j++ {
			start := uint32(i)
			end := uint32(i + 10)
			selection := ReadRangeUint32(start, end, rng)
			if selection < start || selection >= end {
				t.Errorf("out of range: %d < %d >= %d",
					start, selection, end)
			}
		}
	}
}
