////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"github.com/pkg/errors"
	"gitlab.com/xx_network/crypto/rsa"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
)

// NewID creates a new ID by hashing the public key with a random 256-bit number
// and appending the ID type.
// ID's are used by cmix to identify users, gateways, servers, and other network
// services
// You should use this function with csprng:
//
//	rng := csprng.NewSystemRNG()
//	privk, err := rsa.GenerateKey(rng, 4096)
//	pubk := privk.PublicKey
//	// check err
//	salt, err := csprng.Generate(32, rng)
//	// check err
//	id, err := xx.NewID(pubk, salt, IDTypeGateway)
//	// check err
func NewID(key rsa.PublicKey, salt []byte, idType id.Type) (*id.ID, error) {
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
