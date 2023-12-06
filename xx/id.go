////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"crypto/rsa"

	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// GoRsa is an interface for an RSA implementation that may be used by
// NewID. The object adhering to this interface must have a method providing a
// rsa.PublicKey.
type GoRsa interface {
	// GetGoRSA returns the public key in the standard Go crypto/rsa format.
	GetGoRSA() *rsa.PublicKey
}

// NewID creates a new ID by hashing the public key with a random 256-bit salt
// and appending the ID type. IDs are used by cMix to identify users, gateways,
// servers, and other network services (refer to id.Type)
func NewID(key GoRsa, salt []byte, idType id.Type) (*id.ID, error) {
	// Salt's must be 256bit
	if len(salt) != 32 {
		return nil, errors.New("salt must be 32 bytes")
	}
	// We don't support unknown ID Types
	if idType != id.Gateway &&
		idType != id.Node && idType != id.User {
		return nil, errors.New("Unsupported ID Type")
	}

	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate CMixHash")
	}
	pkBytes := PublicKeyBytes(key.GetGoRSA())

	h.Write(pkBytes)
	h.Write(salt)
	digest := h.Sum(nil)
	var newID id.ID
	copy(newID[0:id.ArrIDLen-1], digest)
	newID[id.ArrIDLen-1] = byte(idType)
	return &newID, nil
}
