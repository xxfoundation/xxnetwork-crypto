////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package large

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

////////////////////////////////////////////////////////////////////////////////
// Constructors                                                               //
////////////////////////////////////////////////////////////////////////////////

// Tests that NewInt returns an Int with the same value of the passed int64.
func TestNewInt(t *testing.T) {
	expected := int64(42)
	actual := NewInt(expected).Int64()

	if actual != expected {
		t.Errorf("NewInt did not return expected Int."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that the bytes passed into NewIntFromBytes match the bytes in the
// returned Int.
func TestNewIntFromBytes(t *testing.T) {
	expected := []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88}
	value := NewIntFromBytes(expected)
	actual := value.Bytes()

	if !bytes.Equal(actual, expected) {
		t.Errorf("NewIntFromBytes did not return expected bytes."+
			"\nexpected: %v\nreceived: %v", expected, actual)
	}
}

// Tests that the string passed into NewIntFromString matches the string
// returned from the new Int.
func TestNewIntFromString(t *testing.T) {
	expected := []string{"178567423", "deadbeef"}
	largeInts := []*Int{
		NewIntFromString(expected[0], 10), NewIntFromString(expected[1], 16)}
	actual := []string{largeInts[0].Text(10), largeInts[1].Text(16)}

	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("NewIntFromString did not return expected string."+
				"\nexpected: %s\nreceived: %s", expected[i], actual[i])
		}
	}
}

// Error path: tests NewIntFromString returns nil if the passed in string does
// not match the base.
func TestNewIntFromString_InvalidBaseError(t *testing.T) {
	value := NewIntFromString("185", 5)
	if value != nil {
		t.Errorf("NewIntFromString should return nil if parsing fails: %s",
			value.Text(10))
	}
}

// Tests that the big.Int passed into NewIntFromBigInt matches the big.Int in
// the returned Int.
func TestNewIntFromBigInt(t *testing.T) {
	expected := int64(42)
	expectedBig := big.NewInt(expected)
	actual := NewIntFromBigInt(expectedBig).Int64()

	if actual != expected {
		t.Errorf("NewIntFromBigInt did not return expected Int."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that NewMaxInt returns the correct value for our upper-bound integer.
func TestNewMaxInt(t *testing.T) {
	expected := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	actual := NewMaxInt().Bytes()
	if !bytes.Equal(actual, expected) {
		t.Errorf("NewMaxInt did not return expected Int."+
			"\nexpected: %v\nreceived: %v", expected, actual)
	}
}

// TestNewIntFromUInt makes sure that we can get the same uint64
// out of a new Int that we put into it
// Tests that the uint64 passed into NewIntFromUInt matches the uint64 in the
// returned Int.
func TestNewIntFromUInt(t *testing.T) {
	expected := uint64(1203785)
	actual := NewIntFromUInt(expected).Uint64()

	if actual != expected {
		t.Errorf("NewIntFromUInt did not return expected Int."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that shows that NewIntFromBits can construct a new Int from a word
// array.
func TestNewIntFromBits(t *testing.T) {
	expected := Bits{
		// dead beef isn't good! end animal agriculture!
		0xdeadbeeffeedbacc,
		// once you go to the back, it's not a tea cafe after all
		0x7eacafefacade00f,
	}
	i := NewIntFromBits(expected)

	// As you can see reading this test's output, due to the reversal done
	// during TextVerbose, the second word comes first.
	// But, for Bits and for CGBN, it's in the same little-endian order in the
	// underlying memory.
	t.Log(i.TextVerbose(16, 0))

	actual := i.Bits()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("NewIntFromBits did not return expected Int."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that the result of Int.DeepCopy is identical to the original but has a
// different reference.
func TestInt_DeepCopy(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	tests := 100

	for i := 0; i < tests; i++ {
		lgBytes := make([]byte, rng.Intn(1000))
		rng.Read(lgBytes)
		lg := NewIntFromBytes(lgBytes)

		lgCopy := lg.DeepCopy()
		if lg.Cmp(lgCopy) != 0 {
			t.Errorf("DeepCopy did not return a copy that matches the original."+
				"\nexpected: %s\nreceived: %s", lg.Text(10), lgCopy.Text(10))
		}

		lgCopy.Sub(lgCopy, NewInt(1))
		if lg.Cmp(lgCopy) == 0 {
			t.Errorf("Modified copy matches original."+
				"\nexpected: %s\nreceived: %s", lg.Text(10), lgCopy.Text(10))
		}

		if lg == lgCopy {
			t.Errorf("Original and copy have the same reference."+
				"\noriginal: %p\ncopy:     %p", lg, lgCopy)
		}
	}

}

////////////////////////////////////////////////////////////////////////////////
// Setters                                                                    //
////////////////////////////////////////////////////////////////////////////////

// Tests that modifying an Int via Int.Set sets it to the expected value.
func TestInt_Set(t *testing.T) {
	expected := NewInt(int64(42))
	actual := NewInt(int64(69))
	if actual.Cmp(expected) == 0 {
		t.Error("Original Ints are not different.")
	}

	actual.Set(expected)
	if actual.Cmp(expected) != 0 {
		t.Errorf("Set did not set the correct value."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

// Tests that modifying an Int via Int.SetBigInt sets it to the expected
// big.Int.
func TestInt_SetBigInt(t *testing.T) {
	i64 := int64(42)
	expectedBig := big.NewInt(i64)
	expected := NewInt(i64)
	actual := NewInt(int64(69))
	if actual.Cmp(expected) == 0 {
		t.Error("Original Ints are not different.")
	}

	actual.SetBigInt(expectedBig)
	if actual.Cmp(expected) != 0 {
		t.Errorf("SetBigInt did not set the correct value."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

// Tests that modifying an Int via Int.SetString sets it to the expected string.
func TestInt_SetString(t *testing.T) {
	tests := []struct {
		str      string
		base     int
		expected *Int
	}{
		{"42", 0, NewInt(42)},
		{"100000000", 0, NewInt(100000000)},
		{"-5", 0, NewInt(-5)},
		{"0", 0, NewInt(0)},
		{"f", 0, nil},
		{"182", 5, nil},
		{"9000000000000000000000000000000090090909090909090090909090909090", 0,
			NewIntFromString("9000000000000000000000000000000090090909090909090090909090909090", 10)},
		{"-1", 2, NewInt(-1)},
	}

	for i, tt := range tests {
		actual, aSuccess := NewInt(0).SetString(tt.str, tt.base)

		// Test invalid input making sure it occurs when expected
		if aSuccess == false {
			if actual != nil && tt.expected == nil {
				t.Errorf("SetString did not return expected result (%d)."+
					"\nexpected: %s\nreceived: %s",
					i, tt.expected.Text(10), actual.Text(10))
			}
		} else {
			if actual.Cmp(tt.expected) != 0 {
				t.Errorf("SetString did not return expected result (%d)."+
					"\nexpected: %s\nreceived: %s",
					i, tt.expected.Text(10), actual.Text(10))
			}
		}
	}
}

// Tests that modifying an Int via Int.SetBytes sets it to the expected byte
// slice.
func TestInt_SetBytes(t *testing.T) {
	tests := []struct {
		b        []byte
		expected string
	}{
		{[]byte{0x2A}, "42"},
		{[]byte{0x63, 0xFF, 0xB2}, "6553522"},
		{[]byte{0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20, 0x57, 0xCE, 0xF4,
			0x32, 0xF3}, "867530918239450598372829049587"},
		{[]byte{0x00}, "0"},
	}

	for i, tt := range tests {
		expected := NewIntFromString(tt.expected, 10)
		actual := NewInt(0).SetBytes(tt.b)
		if actual.Cmp(expected) != 0 {
			t.Errorf("SetBytes did not return expected result (%d)."+
				"\nexpected: %s\nreceived: %s",
				i, expected.Text(10), actual.Text(10))
		}
	}
}

// Tests that modifying an Int via Int.SetInt64 sets it to the expected int64.
func TestInt_SetInt64(t *testing.T) {
	expected := NewInt(int64(42))
	actual := NewInt(int64(69))
	actual.SetInt64(expected.Int64())

	if actual.Cmp(expected) != 0 {
		t.Errorf("SetInt64 did not return expected result."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

// Tests that modifying an Int via Int.SetUint64 sets it to the expected uint64.
func TestInt_SetUint64(t *testing.T) {
	expected := NewInt(int64(42))
	actual := NewInt(int64(69))
	actual.SetUint64(expected.Uint64())

	if actual.Cmp(expected) != 0 {
		t.Errorf("SetUint64 did not return expected result."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

// Tests that modifying an Int via Int.SetBits sets it to the expected Bits.
// This test will fail on 32-bit machines.
func TestInt_SetBits(t *testing.T) {
	expected := NewIntFromString(
		"1245967457601407658012964425109124356120693", 10)
	actual := NewInt(int64(99))
	actual.SetBits(Bits{5168612429366960245, 10501165033672452302, 3661})

	if actual.Cmp(expected) != 0 {
		t.Errorf("SetBits did not return expected result."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Converters                                                                 //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.BigInt converts the Int to a big.Int.
func TestInt_BigInt(t *testing.T) {
	expected := big.NewInt(int64(42))
	actual := NewInt(int64(42)).BigInt()

	if actual.Cmp(expected) != 0 {
		t.Errorf("BigInt did not return expected big.Int."+
			"\nexpected: %s\nreceived: %s", expected.Text(10), actual.Text(10))
	}
}

// Tests that Int.Int64 converts the Int to the original int64.
func TestInt_Int64(t *testing.T) {
	expected := int64(42)
	actual := NewInt(int64(42)).Int64()

	if actual != expected {
		t.Errorf("Int64 did not return expected int64."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that Int.Uint64 converts the Int to the original uint64.
func TestInt_Uint64(t *testing.T) {
	expected := uint64(42)
	actual := NewIntFromUInt(uint64(42)).Uint64()

	if actual != expected {
		t.Errorf("Uint64 did not return expected int64."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// Tests that Int.IsInt64 correctly determines if the Int can be converted or
// not for a list of Ints.
func TestInt_IsInt64(t *testing.T) {
	tests := []struct {
		z        *Int
		expected bool
	}{
		{NewInt(0), true},
		{NewInt(1000000), true},
		{NewInt(9223372036854775807), true},
		{NewIntFromString("9223372036854775808", 10), false},
		{NewInt(-1), true},
		{NewInt(-9223372036854775808), true},
		{NewIntFromString("-9223372036854775809", 10), false},
	}

	for i, tt := range tests {
		actual := tt.z.IsInt64()
		if actual != tt.expected {
			t.Errorf("IsInt64 returned unexpected result for Int %s (%d)."+
				"\nexpected: %t\nreceived: %t",
				tt.z.Text(10), i, tt.expected, actual)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Basic Arithmetic Operators                                                 //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.Add returns the expected results.
func TestInt_Add(t *testing.T) {
	tests := []struct{ x, y, z, expected *Int }{
		{NewInt(42), NewInt(69), NewInt(30), NewInt(111)},
		{NewInt(0), NewInt(69), NewInt(0), NewInt(69)},
		{NewInt(-50), NewInt(69), NewInt(10000), NewInt(19)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30),
			NewIntFromString("9223372036854775817", 10)},
	}

	for i, tt := range tests {
		actual := tt.z.Add(tt.x, tt.y)
		if actual.Cmp(tt.expected) != 0 {
			t.Errorf("Add returned unexpected result for %s + %s (%d)."+
				"\nexpected: %s\nreceived: %s", tt.x.Text(10), tt.y.Text(10), i,
				tt.expected.Text(10), actual.Text(10))
		}
	}
}

// Tests that Int.Sub returns the expected results.
func TestInt_Sub(t *testing.T) {
	tests := []struct{ x, y, expected string }{
		{"42", "42", "0"},
		{"42", "69", "-27"},
		{"69", "42", "27"},
		{"-69", "42", "-111"},
		{"-69", "-42", "-27"},
		{"1000000000", "1000000000", "0"},
		{"1000000000", "9999999999999999999999", "-9999999999998999999999"},
		{"9999999999999999999999", "1000000000", "9999999999998999999999"},
	}

	for i, tt := range tests {
		x, y := NewIntFromString(tt.x, 10), NewIntFromString(tt.y, 10)
		expected := NewIntFromString(tt.expected, 10)
		actual := NewInt(0).Sub(x, y)
		if actual.Cmp(expected) != 0 {
			t.Errorf("Sub returned unexpected result for %s - %s (%d)."+
				"\nexpected: %s\nreceived: %s", x.Text(10), y.Text(10), i,
				expected.Text(10), actual.Text(10))
		}
	}

}

// Tests that Int.Mul returns the expected results.
func TestInt_Mul(t *testing.T) {
	tests := []struct{ x, y, z, expected *Int }{
		{NewInt(42), NewInt(69), NewInt(30), NewInt(2898)},
		{NewInt(0), NewInt(69), NewInt(0), NewInt(0)},
		{NewInt(-50), NewInt(69), NewInt(10000), NewInt(-3450)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30),
			NewIntFromString("92233720368547758070", 10)},
	}

	for i, tt := range tests {
		actual := tt.z.Mul(tt.x, tt.y)
		if actual.Cmp(tt.expected) != 0 {
			t.Errorf("Sub returned unexpected result for %s * %s (%d)."+
				"\nexpected: %s\nreceived: %s", tt.x.Text(10), tt.y.Text(10), i,
				tt.expected.Text(10), actual.Text(10))
		}
	}
}

// Tests that Int.Div returns the expected results.
func TestInt_Div(t *testing.T) {
	tests := []struct{ x, y, expected string }{
		{"42", "42", "1"},
		{"42", "-42", "-1"},
		{"42", "69", "0"},
		{"69", "42", "1"},
		{"-69", "42", "-2"},
		{"-69", "-42", "2"},
		{"1000000000", "1000000000", "1"},
		{"1000000000", "9999999999999999999999", "0"},
		{"9999999999999999999999", "1000000000", "9999999999999"},
	}

	for i, tt := range tests {
		x, y := NewIntFromString(tt.x, 10), NewIntFromString(tt.y, 10)
		expected := NewIntFromString(tt.expected, 10)
		actual := NewInt(0).Div(x, y)
		if actual.Cmp(expected) != 0 {
			t.Errorf("Div returned unexpected result for %s / %s (%d)."+
				"\nexpected: %s\nreceived: %s", x.Text(10), y.Text(10), i,
				expected.Text(10), actual.Text(10))
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Operators with Modulo                                                      //
////////////////////////////////////////////////////////////////////////////////

// TestMod checks if the Mod operation returns the correct result
func TestInt_Mod(t *testing.T) {
	tests := []struct{ x, m, expected string }{
		{"42", "42", "0"},
		{"42", "69", "42"},
		{"69", "42", "27"},
		{"1000000000", "11", "10"},
		{"1000000000", "9999999999999999999999", "1000000000"},
		{"9999999999999999999999", "10000", "9999"},
	}

	for i, tt := range tests {
		x, m := NewIntFromString(tt.x, 10), NewIntFromString(tt.m, 10)
		expected := NewIntFromString(tt.expected, 10)
		result := NewInt(0).Mod(x, m)

		if result.Cmp(expected) != 0 {
			t.Errorf("Mod did not return the expected result (%d)."+
				"\nexpected: %s\nreceived: %s",
				i, expected.Text(10), result.Text(10))
		}
	}
}

// Tests that Int.ModInverse returns the expected result.
func TestInt_ModInverse(t *testing.T) {
	expected := NewInt(1)
	tests := []struct{ x, n string }{
		{"3", "11"},
		{"42", "11"},
		{"100000", "15487469"},
	}

	for i, tt := range tests {
		x, n := NewIntFromString(tt.x, 10), NewIntFromString(tt.n, 10)
		result := NewInt(0).ModInverse(x, n)

		reMultiply := NewInt(0).Mul(x, result)
		reMultiply = reMultiply.Mod(reMultiply, n)

		if expected.Cmp(reMultiply) != 0 {
			t.Errorf("ModInverse did not return the expected result (%d)."+
				"\nexpected: %s\nreceived: %s",
				i, expected.Text(10), reMultiply.Text(10))
		}
	}
}

// Error path: tests that the Int.ModInverse returns nil when no inverse can be
// found (occurs when x and n are not relatively prime).
func TestInt_ModInverse_InputNotRelativelyPrime(t *testing.T) {
	n := NewInt(100)
	x := NewInt(20)

	result := NewInt(1).ModInverse(x, n)
	if result != nil {
		t.Errorf("ModInverse should have return nil when x (%s) and n (%s) "+
			"are not relatively prime.\nexpected: %v\nreceived: %s",
			x.Text(10), n.Text(10), nil, result.Text(10))
	}
}

// Tests that Int.Exp returns the expected result for various Ints.
func TestInt_Exp(t *testing.T) {
	tests := []struct{ x, y, m, expected string }{
		{"42", "42", "11", "4"},
		{"42", "69", "31", "23"},
		{"-69", "42", "17", "1"},
		{"1000000000", "9999999", "12432332443", "6589464193"},
	}

	for i, tt := range tests {
		x, y := NewIntFromString(tt.x, 10), NewIntFromString(tt.y, 10)
		m := NewIntFromString(tt.m, 10)
		expected := NewIntFromString(tt.expected, 10)
		result := NewInt(0).Exp(x, y, m)
		if result.Cmp(expected) != 0 {
			t.Errorf("Exp did not return the expected result (%d)."+
				"\nexpected: %s\nreceived: %s",
				i, expected.Text(10), result.Text(10))
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// GCD Operator                                                               //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.GCD finds the correct greatest common denominator.
func TestInt_GCD(t *testing.T) {
	a, b := NewInt(178919), NewInt(987642)

	// These will be filled in by GCD and can calculate modular inverse
	x, y := NewInt(0), NewInt(0)

	actual := NewInt(0).GCD(x, y, a, b)
	expected := NewInt(1)
	if actual.Cmp(expected) != 0 {
		t.Errorf("GCD did not find the GCD.\nexpected: %s\nreceived: %s",
			expected.Text(10), actual.Text(10))
	}

	// Use results of extended GCD to calculate modular inverse and check
	// consistency with ModInverse
	if x.Cmp(NewInt(0)) < 0 {
		// Add the prime in again to put the result back in the group
		x.Add(x, b)
	}

	modInverseResult := NewInt(0).ModInverse(a, b)
	if x.Cmp(modInverseResult) != 0 {
		t.Errorf("Incorrect modular inverse.\nexpected: %s\nreceived: %s",
			modInverseResult.Text(10), x.Text(10))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous Operators                                                    //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.IsCoprime returns the expected result.
func TestInt_IsCoprime(t *testing.T) {
	tests := []struct {
		a, b     *Int
		expected bool
	}{
		{NewInt(50580), NewInt(0), false}, // 0 Cannot be coprime
		{NewInt(50580), NewInt(1), true},  // 1 is always coprime
		{NewInt(50580), NewInt(49), true},
	}
	for i, tt := range tests {
		received := tt.a.IsCoprime(tt.b)
		if received != tt.expected {
			t.Errorf("IsCoprime incorrect checked if %s is a coprime of "+
				"%s (%d).\nexpected: %t\nreceived: %t",
				tt.b.Text(10), tt.a.Text(10), i, tt.expected, received)
		}
	}
}

// Tests that Int.FillBytes fills the expected bytes.
func TestInt_FillBytes(t *testing.T) {
	for _, n := range []string{
		"0",
		"1000",
		"0xffffffff",
		"-0xffffffff",
		"0xffffffffffffffff",
		"0x10000000000000000",
		"0xabababababababababababababababababababababababababa",
		"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		x := NewIntFromString(n, 0)
		buf := make([]byte, x.ByteLen())
		got := NewInt(0).SetBytes(x.FillBytes(buf))
		if got.BigInt().CmpAbs(x.BigInt()) != 0 {
			t.Errorf("FillBytes error.\nexpected: %s\nreceived: %s",
				x.Text(10), got.Text(10))
		}
	}
}

// Tests that Int.IsPrime correctly determines if a number is prime or not.
func TestInt_IsPrime(t *testing.T) {
	n := NewInt(101) // 101 is prime
	if !n.IsPrime() {
		t.Errorf("IsPrime: %d should be prime!", n.Uint64())
	}

	n = NewInt(63) // 63 is NOT prime
	if n.IsPrime() {
		t.Errorf("IsPrime: %d should NOT be prime!", n.Uint64())
	}
}

// Tests that Int.BitLen returns the expected bit length.
func TestInt_BitLen(t *testing.T) {
	tests := []struct {
		z        *Int
		expected int
	}{
		{NewInt(42), 6},
		{NewInt(6553522), 23},
		{NewIntFromString("867530918239450598372829049587", 10), 100},
		{NewInt(-42), 6},
	}

	for i, tt := range tests {
		actual := tt.z.BitLen()
		if actual != tt.expected {
			t.Errorf("BitLen returned unexpected value (%d)."+
				"\nexpected: %d\nreceived: %d", i, actual, tt.expected)
		}
	}
}

// Tests that Int.ByteLen returns the expected byte length.
func TestInt_ByteLen(t *testing.T) {
	tests := []struct {
		z        *Int
		expected int
	}{
		{NewInt(2), 1},       // 2 bits  -->  1 bytes (where +6 works)
		{NewInt(8388608), 3}, // 24 bits -->  3 bytes (exactly)
		{NewIntFromString("867530918239450598372829049587", 10), 13}, // 100 bits --> 13 bytes (where +4 works)
		{NewInt(-42), 1}, // 6 bits  -->  1 byte
	}

	for i, tt := range tests {
		actual := tt.z.ByteLen()
		if actual != tt.expected {
			t.Errorf("ByteLen returned unexpected value (%d)."+
				"\nexpected: %d\nreceived: %d", i, actual, tt.expected)
		}
	}
}

// Tests that Int.Cmp returns the expected result.
func TestInt_Cmp(t *testing.T) {
	tests := []struct {
		x, y     *Int
		expected int
	}{
		{NewInt(42), NewInt(69), -1}, // x < y
		{NewInt(42), NewInt(42), 0},  // x == y
		{NewInt(69), NewInt(42), 1},  // x > y
	}

	for i, tt := range tests {
		result := tt.x.Cmp(tt.y)
		if result != tt.expected {
			t.Errorf("Cmp returned unexpected value when comparing %s to %s (%d)."+
				"\nexpected: %d\nreceived: %d",
				tt.x.Text(10), tt.y.Text(10), i, tt.expected, result)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Bitwise Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.LeftShift mimics the Go >> operator.
func TestInt_RightShift(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		a := rng.Uint64()
		shift := uint(rng.Intn(63))
		expected := a >> shift
		actual := NewInt(0).RightShift(NewIntFromUInt(a), shift)

		if actual.Uint64() != expected {
			t.Errorf("RightShift did not return the expected result for "+
				"%d >> %d (%d).\nexpected: %d\nReceived: %d",
				a, shift, i, expected, actual.Uint64())
		}
	}
}

// Tests that Int.LeftShift mimics the Go << operator.
func TestInt_LeftShift(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		a := rng.Uint64()
		shift := uint(rng.Intn(63))

		expected := a << shift
		actual := NewInt(0).LeftShift(NewIntFromUInt(a), shift)

		if actual.Uint64() != expected {
			t.Errorf("LeftShift did not return the expected result for "+
				"%d << %d (%d).\nexpected: %d\nReceived: %d",
				a, shift, i, expected, actual.Uint64())
		}
	}
}

// Tests that Int.Or mimics the Go | operator.
func TestInt_Or(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		a, b := rng.Uint64(), rng.Uint64()
		val1, val2 := NewIntFromUInt(a), NewIntFromUInt(b)

		expected := a | b
		actual := NewInt(0).Or(val1, val2)

		if actual.Uint64() != expected {
			t.Errorf("Or did not return the expected result for %d | %d (%d)."+
				"\nexpected: %d\nReceived: %d",
				a, b, i, expected, actual.Uint64())
		}
	}
}

// Tests that Int.Xor mimics the Go ^ operator.
func TestInt_Xor(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		a, b := rng.Uint64(), rng.Uint64()
		val1, val2 := NewIntFromUInt(a), NewIntFromUInt(b)

		expected := a ^ b
		actual := NewInt(0).Xor(val1, val2)

		if actual.Uint64() != expected {
			t.Errorf("Xor did not return the expected result for %d ^ %d (%d)."+
				"\nexpected: %d\nReceived: %d",
				a, b, i, expected, actual.Uint64())
		}
	}
}

// Tests that Int.And mimics the Go & operator.
func TestInt_And(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		a, b := rng.Uint64(), rng.Uint64()
		val1, val2 := NewIntFromUInt(a), NewIntFromUInt(b)

		expected := a & b
		actual := NewInt(0).And(val1, val2)

		if actual.Uint64() != expected {
			t.Errorf("And did not return the expected result for %d & %d (%d)."+
				"\nexpected: %d\nReceived: %d",
				a, b, i, expected, actual.Uint64())
		}
	}
}

// Benchmark for Int.Xor.
func BenchmarkXor(b *testing.B) {
	rng := rand.New(rand.NewSource(42))
	val1, val2 := make([]*Int, b.N), make([]*Int, b.N)
	byteField := make([]byte, 256)
	for i := 0; i < b.N; i++ {
		rng.Read(byteField)
		val1[i] = NewIntFromBytes(byteField)
		rng.Read(byteField)
		val2[i] = NewIntFromBytes(byteField)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewInt(0).Xor(val1[i], val2[i])
	}
}

////////////////////////////////////////////////////////////////////////////////
// Byte Slice Getters                                                         //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.Bytes returns the expected bytes.
func TestInt_Bytes(t *testing.T) {
	tests := []struct {
		z        *Int
		expected []byte
	}{
		{NewInt(42), []byte{0x2A}},
		{NewInt(6553522), []byte{0x63, 0xFF, 0xB2}},
		{NewIntFromString("867530918239450598372829049587", 10),
			[]byte{0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20, 0x57, 0xCE,
				0xF4, 0x32, 0xF3}},
		{NewInt(-42), []byte{0x2A}}, // TODO: Should be <nil>, not 42
	}

	for i, tt := range tests {
		actual := tt.z.Bytes()
		if !reflect.DeepEqual(tt.expected, actual) {
			t.Errorf("Bytes did not return the expected bytes (%d)."+
				"\nexpected: %v\nreceived: %v", i, tt.expected, actual)
		}
	}
}

// Tests that Int.LeftpadBytes returns the correctly left-padded byte strings.
func TestInt_LeftpadBytes(t *testing.T) {
	tests := []struct {
		z        *Int
		length   uint64
		expected []byte
	}{
		{NewInt(420), 3, []byte{0, 1, 164}},
		{NewInt(6553522), 7, []byte{0, 0, 0, 0, 99, 255, 178}},
		{NewInt(0), 5, []byte{0, 0, 0, 0, 0}},
		{NewInt(-42), 8, []byte{0, 0, 0, 0, 0, 0, 0, 42}},
	}

	for i, tt := range tests {
		actual := tt.z.LeftpadBytes(tt.length)
		if !bytes.Equal(actual, tt.expected) {
			t.Errorf("LeftpadBytes did not return the expected value (%d)."+
				"\nexpected: %v\nreceived: %v", i, tt.expected, actual)
		}
	}
}

// Tests that Int.LeftpadBytes panics when the requested length is smaller than
// the actual length of the Int.
func TestInt_LeftpadBytes_Panic(t *testing.T) {
	z := NewInt(6553522)
	length := uint64(2)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("LeftpadBytes did not panic when "+
				"length (%d) < Int byte length (%d).", length, z.ByteLen())
		}
	}()

	z.LeftpadBytes(length)
}

////////////////////////////////////////////////////////////////////////////////
// String Representation Getters                                              //
////////////////////////////////////////////////////////////////////////////////

// Tests that Int.Text returns the expected string.
func TestInt_Text(t *testing.T) {
	tests := []struct {
		z        *Int
		expected string
	}{
		{NewInt(42), "42"},
		{NewInt(6553522), "6553522"},
		{NewIntFromString("867530918239450598372829049587", 10), "8675309182..."},
		{NewInt(-42), "-42"}, // TODO: Should be <nil>, not -42
	}

	for i, tt := range tests {
		actual := tt.z.Text(10)
		if actual != tt.expected {
			t.Errorf("Text did not return expected value (%d)."+
				"\nexpected: %s\nreceived: %s", i, tt.expected, actual)
		}
	}
}

// Tests that Int.TextVerbose returns the expected string.
func TestInt_TextVerbose(t *testing.T) {
	tests := []struct {
		z        string
		length   int
		expected string
	}{
		{"867530918239450598372829049587", 12, "867530918239..."},
		{"867530918239450598372829049587", 16, "8675309182394505..."},
		{"867530918239450598372829049587", 18, "867530918239450598..."},
		{"867530918239450598372829049587", 0, "867530918239450598372829049587"},
	}

	for i, tt := range tests {
		z := NewIntFromString(tt.z, 10)
		actual := z.TextVerbose(10, tt.length)
		if actual != tt.expected {
			t.Errorf("TextVerbose did not return expected value for length "+
				"%d (%d).\nexpected: %s\nreceived: %s",
				tt.length, i, tt.expected, actual)
		}
	}
}

// Tests that Int.Bits returns the correct underlying Bits.
func TestInt_Bits(t *testing.T) {
	testInt := NewIntFromString("867530918239450598372829049587", 10)
	actual := testInt.Bits()
	expected := Bits{12503998451923825395, 47028945312}
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Bits did not return expected Bits."+
			"\nexpected: %v\nreceived: %v", expected, actual)
	}
}

////////////////////////////////////////////////////////////////////////////////
// GOB Operators                                                              //
////////////////////////////////////////////////////////////////////////////////

// Tests that an Int can be encoded and decoded using the gob.Encoder and
// gob.Decoder.
func TestGob(t *testing.T) {
	buff := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buff)
	dec := gob.NewDecoder(buff)

	inInt := NewInt(42)
	if err := enc.Encode(inInt); err != nil {
		t.Fatalf("Failed to gob encode Int: %+v", err)
	}

	outInt := NewInt(0)
	if err := dec.Decode(&outInt); err != nil {
		t.Fatalf("Failed to gob decode Int: %+v", err)
	}

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("Failed to gob encode/decode.\nexpected: %s\nreceived: %s",
			inInt.Text(10), outInt.Text(10))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Marshal Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

// Tests that an Int can be JSON marshalled and unmarshalled via json.Marshal
// and json.Unmarshal.
func TestInt_MarshalJSON_UnmarshalJSON(t *testing.T) {
	inInt := NewInt(42)

	data, err := json.Marshal(inInt)
	if err != nil {
		t.Fatalf("Failed to JSON marshal Int: %+v", err)
	}

	outInt := NewInt(0)
	err = json.Unmarshal(data, outInt)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal Int: %+v", err)
	}

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("Failed to JSON marshal and unmarshal Int."+
			"\nexpected: %s\nreceived: %s", inInt.Text(10), outInt.Text(10))
	}
}

// Error path: tests that Int.UnmarshalJSON returns an error for an invalid
// marshalled Int.
func TestInt_UnmarshalJSON_InvalidIntError(t *testing.T) {
	outInt := NewInt(5)
	err := outInt.UnmarshalJSON([]byte("\"abc\""))
	if err == nil {
		t.Error("UnmarshalJSON did not produce an error for invalid Int data.")
	}

	if outInt.Cmp(NewInt(5)) != 0 {
		t.Errorf("Unmarshalled Int changed on error."+
			"\nexpected: %s\nreceived: %s", NewInt(5).Text(10), outInt.Text(10))
	}
}
