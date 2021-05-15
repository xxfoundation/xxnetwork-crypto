////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wallet

import "errors"

const (
	purpose    = uint32(0x8000002C) // 44'
	coinTypeXX = uint32(0x800007A3) // 1955'
	pathSize   = 5
)

type Path []uint32

// Create path from given account, params and nonce
func NewPath(account, params, nonce uint32) (Path, error) {
	p := make(Path, pathSize)

	if account >= firstHardened || params >= firstHardened || nonce >= firstHardened {
		return nil, errors.New("NewPath: invalid path")
	}

	p[0] = purpose
	p[1] = coinTypeXX
	p[2] = account | firstHardened
	p[3] = params | firstHardened
	p[4] = nonce | firstHardened

	return p, nil
}

// Compute BIP32 node from seed and path
func ComputeNode(seed []byte, path Path) (*Node, error) {
	// Check Path Size
	if len(path) != pathSize {
		return nil, errors.New("ComputeNode: path has wrong length")
	}

	// Create Master node
	n, err := NewMasterNode(seed)
	if err != nil {
		return nil, err
	}

	// Iterate path and Compute children
	for _, idx := range path {
		err := n.ComputeHardenedChild(idx)
		if err != nil {
			return nil, err
		}
	}

	return n, nil
}
