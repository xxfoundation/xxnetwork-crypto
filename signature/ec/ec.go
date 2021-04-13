////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package ec contains logic for handling elliptic curve keys

package ec

import (
	"crypto/rand"
	"fmt"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/pkg/errors"
)

// UnmarshalEllipticPublicKey generates an elliptic curve key pair.
// Then using the eddsa library to deserialize publicKeyStr into an
// EC public key
func UnmarshalEllipticPublicKey(publicKeyStr string) (*eddsa.PublicKey, error) {
	// Generate a key to unmarshal
	ecKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Could not generate an EC key"))
	}

	ecPublicKey := ecKey.PublicKey()
	if err = ecPublicKey.FromString(publicKeyStr); err != nil {
		return nil, errors.WithMessage(err, fmt.Sprint("Could not parse public key string"))
	}

	return ecPublicKey, nil

}
