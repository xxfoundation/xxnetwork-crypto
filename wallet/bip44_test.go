////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import (
	"crypto/rand"
	"testing"
)

func TestNewPath(t *testing.T) {
	// Test path with invalid account, params and nonce indexes
	_, err := NewPath(firstHardened, 0, 0)

	if err == nil {
		t.Fatalf("NewPath() should return error when account index is too large")
	}

	_, err = NewPath(0, firstHardened, 0)

	if err == nil {
		t.Fatalf("NewPath() should return error when params index is too large")
	}

	_, err = NewPath(0, 0, firstHardened)

	if err == nil {
		t.Fatalf("NewPath() should return error when nonce index is too large")
	}

	// Test valid path
	p, err := NewPath(0, 0, 0)

	if err != nil {
		t.Fatalf("NewPath() shouldn't return error when indexes are valid")
	}

	// Make sure path is properly generated
	if len(p) != pathSize {
		t.Fatalf("NewPath(): path has incorrect size. Got %d, expected %d", len(p), pathSize)
	}

	if p[0] != purpose {
		t.Fatalf("NewPath(): first path index is incorrect. Got %d, expected %d", p[0], purpose)
	}

	if p[1] != coinTypeXX {
		t.Fatalf("NewPath(): second path index is incorrect. Got %d, expected %d", p[1], coinTypeXX)
	}

	if p[2] != firstHardened {
		t.Fatalf("NewPath(): third path index is incorrect. Got %d, expected %d", p[2], firstHardened)
	}

	if p[3] != firstHardened {
		t.Fatalf("NewPath(): fourth path index is incorrect. Got %d, expected %d", p[3], firstHardened)
	}

	if p[4] != firstHardened {
		t.Fatalf("NewPath(): fifth path index is incorrect. Got %d, expected %d", p[4], firstHardened)
	}
}

func TestComputeNode(t *testing.T) {
	// Test wrong path size
	path := []uint32{0, 0, 0}

	_, err := ComputeNode(nil, path)

	if err == nil {
		t.Fatalf("ComputeNode() should return error when path has incorrect size")
	}

	// Test nil seed
	path = []uint32{0, 0, 0, 0, 0}

	_, err = ComputeNode(nil, path)

	if err == nil {
		t.Fatalf("ComputeNode() should return error when seed is nil")
	}

	// Test invalid path (containing soft derivations)
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	path, _ = NewPath(0, 0, 0)
	path[pathSize-1] = 0

	_, err = ComputeNode(seed, path)

	if err == nil {
		t.Fatalf("ComputeNode() should return error if path contains soft derivations")
	}

	// Test valid path
	path, _ = NewPath(0, 0, 0)

	_, err = ComputeNode(seed, path)

	if err != nil {
		t.Fatalf("ComputeNode() should not return error for valid seed and path")
	}
}
