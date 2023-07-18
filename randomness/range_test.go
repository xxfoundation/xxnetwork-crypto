////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"math/rand"
	"strings"
	"testing"
)

// Tests that the results of ReadRangeUint32 gets random numbers from inside the
// right range. It verifies that it is in the range.
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

// Test that ReadRangeUint32 panics when the RNG does not return enough data.
func TestReadRangeUint32_ReadRangeShortPanic(t *testing.T) {
	rng := strings.NewReader("ts")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("ReadRangeUint32 should panic on short read")
		}
	}()

	ReadRangeUint32(0, 10, rng)
}
