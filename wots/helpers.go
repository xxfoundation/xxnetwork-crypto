////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"encoding/binary"
	"hash"
)

func prf(dst []byte, h hash.Hash, seed []byte, idx uint8) []byte {
	h.Reset()
	h.Write(seed)
	h.Write([]byte{idx})
	return h.Sum(dst)
}

func chain(dst []byte, h hash.Hash, seed []byte, idx uint8, maskedMsg []byte) []byte {
	h.Reset()
	h.Write(seed)
	h.Write([]byte{idx})
	h.Write(maskedMsg)
	return h.Sum(dst)
}

func checksum(msg []byte) []byte {
	sum := uint16(W-1) * uint16(len(msg))
	for _, b := range msg {
		sum -= uint16(b)
	}
	if len(msg) == 1 {
		return []byte{uint8(sum)}
	}
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, sum)
	return out
}

func computeRands(n int, pSeed []byte, h hash.Hash) [][]byte {
	// Buffer for hashing
	buf := make([]byte, 0, h.Size())
	// Random elements memory
	rands := make([][]byte, W-1)
	for i := range rands {
		rands[i] = make([]byte, n)
	}

	// Compute all random elements
	// There is one random element for each ladder depth, 1 to W-1
	for i := uint8(0); i < W-1; i++ {
		// Rands[i] = H(PKSEED || i+1)
		buf = prf(buf, h, pSeed, i+1)
		copy(rands[i], buf[0:n])
		buf = buf[:0]
	}
	return rands
}

// Check parity of value
func parity(value []byte) bool {
	count := 0
	for _, n := range value {
		n^=n>>4
		n^=n>>2
		n^=n>>1
		count += int(n&1)
	}
	return count % 2 == 1
}
