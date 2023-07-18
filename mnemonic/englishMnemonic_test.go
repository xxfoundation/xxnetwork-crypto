////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package mnemonic

import (
	"bytes"
	"testing"
)

type TestByteBuf struct {
	self *bytes.Buffer
}

func (b TestByteBuf) Read(x []byte) (int, error) {
	return b.self.Read(x)
}
func (b TestByteBuf) SetSeed([]byte) error { return nil }

// TestMnemonic is a general smoke test for the mnemonic system
func TestMnemonic(t *testing.T) {
	entropy := []byte("abcdefghijklmnopqrstuvwxyzabcdef")
	notAnRng := TestByteBuf{self: bytes.NewBuffer(entropy)}

	badMnemonic, err := GenerateMnemonic(notAnRng, 8675309)
	if err == nil || badMnemonic != "" {
		t.Errorf("Should not have been able to create mnemonic!")
	}

	mnemonic, err := GenerateMnemonic(notAnRng, 32)
	if err != nil {
		t.Errorf("%+v", err)
	}

	originalEntropy, err := DecodeMnemonic(mnemonic)
	if err != nil {
		t.Errorf("%+v", err)
	}
	if !bytes.Equal(originalEntropy, entropy) {
		t.Errorf("Unable to read entropy that was put in")
	}
}
