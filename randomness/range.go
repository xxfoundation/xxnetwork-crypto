////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package randomness

import (
	"encoding/binary"
	"io"
	"math"

	jww "github.com/spf13/jwalterweatherman"
)

// ReadUint32 reads an integer from an io.Reader (which should be a CSPRNG).
func ReadUint32(rng io.Reader) uint32 {
	var rndBytes [4]byte
	i, err := rng.Read(rndBytes[:])
	if i != 4 || err != nil {
		jww.FATAL.Panicf("cannot read from rng: %+v", err)
	}
	return binary.BigEndian.Uint32(rndBytes[:])
}

// ReadRangeUint32 reduces a random integer from 0, MaxUint32 to
// greater than or equal to start and less than end
//
// The reason start is inclusive and end is not is that this function
// is meant to work with lists (i.e., get random element inside the list,
// except for the first 3)
func ReadRangeUint32(start, end uint32, rng io.Reader) uint32 {
	size := end - start
	// Note that we could just do the part inside the () here, but
	// then extra can == size which means a little range is
	// wasted; either choice seems negligible, so we went with the
	// "more correct"
	extra := (math.MaxUint32%size + 1) % size
	limit := math.MaxUint32 - extra
	// Loop until we read something inside the limit
	for {
		res := ReadUint32(rng)
		if res <= limit {
			return (res % size) + start
		}
	}
}
