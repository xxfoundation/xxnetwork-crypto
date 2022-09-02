////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xx

import (
	"testing"
)

func TestIntToBytes(t *testing.T) {
	x := IntToBytes(1)
	if byte(1) != x[7] {
		t.Errorf("Int ToBytes: %d != %v", 1, x)
	}

	x = IntToBytes(-1)
	for i := 0; i < 8; i++ {
		if x[i] != 0xFF {
			t.Errorf("IntToBytes: %d != %v", -1, x)
		}
	}

	x = IntToBytes(65535)
	for i := 0; i < 8; i++ {
		if (i > 6 && x[i] != 0xFF) &&
			(i <= 6 && x[i] != 0) {
			t.Errorf("IntToBytes: %d != %v", -1, x)
		}
	}
}
