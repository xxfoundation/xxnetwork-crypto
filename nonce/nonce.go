////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package nonce contains our implementation of a nonce, including an expiration
// time, generation time and TTL.
package nonce

import (
	"time"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/csprng"
)

const (
	// NonceLen is the length of [Nonce] in bytes.
	NonceLen = 32

	// RegistrationTTL is the TTL of registration nonce in seconds.
	RegistrationTTL = 180
)

type Value [NonceLen]byte

type Nonce struct {
	Value
	GenTime    time.Time
	ExpiryTime time.Time
	TTL        time.Duration
}

// NewNonce generate a fresh nonce with the given TTL in seconds
func NewNonce(ttl uint) (Nonce, error) {
	if ttl == 0 {
		jww.FATAL.Panicf("TTL cannot be 0")
	}
	newValue := make([]byte, NonceLen)
	randGen := csprng.SystemRNG{}
	size, err := randGen.Read(newValue)
	if err != nil || size != len(newValue) {
		jww.FATAL.Panicf("Could not generate nonce: %+v", err)
	}
	newNonce := Nonce{GenTime: time.Now(),
		TTL: time.Duration(ttl) * time.Second}
	copy(newNonce.Value[:], newValue)
	newNonce.ExpiryTime = newNonce.GenTime.Add(newNonce.TTL)
	return newNonce, err
}

// Bytes returns the nonce's value in a byte slice
func (n Nonce) Bytes() []byte {
	return n.Value[:]
}

// IsValid checks that the nonce has not expired
func (n Nonce) IsValid() bool {
	return time.Now().Before(n.ExpiryTime)
}
