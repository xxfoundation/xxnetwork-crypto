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
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

////////////////////////////////////////////////////////////////////////////////
// Constructors                                                               //
////////////////////////////////////////////////////////////////////////////////

// TestNewInt checks if the NewInt function returns an Int with the same value
// of the passed int64.
func TestNewInt(t *testing.T) {
	expected := int64(42)
	actual := NewInt(int64(42)).Int64()

	if actual != expected {
		t.Errorf("NewInt did not return expected Int."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// TestNewIntFromBytes makes sure that we can get the same byte string
// out of a new Int that we put into it
func TestNewIntFromBytes(t *testing.T) {
	expected := []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88}
	value := NewIntFromBytes(expected)
	actual := value.Bytes()

	if !bytes.Equal(actual, expected) {
		t.Errorf("NewIntFromBytes did not return expected bytes."+
			"\nexpected: %d\nreceived: %d", expected, actual)
	}
}

// TestNewIntFromString ensures that we get the same character string
// out of a new Int that we put into it
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

	// Test that error in parsing string returns nil
	value := NewIntFromString("185", 5)
	if value != nil {
		t.Errorf(
			"NewIntFromString should return nil if parsing fails: %v", value)
	}
}

// TestNewIntFromBigInt checks if the NewIntFromBigInt function returns an Int
// with the same value of the passed bigInt.
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
		t.Error("NewMaxInt: actual differed from expected")
	}
}

// TestNewIntFromUInt makes sure that we can get the same uint64
// out of a new Int that we put into it
func TestNewIntFromUInt(t *testing.T) {
	expected := uint64(1203785)

	actual := NewIntFromUInt(expected).Uint64()

	if actual != expected {
		t.Error("NewIntFromUInt: expected", expected,
			"got", actual)
	}
}

// TestNewIntFromBits shows that a new int can be constructed from a word array
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
		t.Errorf("ints differed. expected: %+v, got %+v", expected, actual)
	}
}

// Tests that the DeepCopy is identical and that it is separate from the original
func TestInt_DeepCopy(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	tests := 100

	for i := 0; i < tests; i++ {
		lgBytes := make([]byte, rng.Int()%1000)
		lg := NewIntFromBytes(lgBytes)

		lgCopy := lg.DeepCopy()

		if lg.Cmp(lgCopy) != 0 {
			t.Errorf("Int.DeepCopy: Copy not equal to original, Expected: %v, Received: %v",
				lg.Text(16), lgCopy.Text(16))
		}

		lgCopy.Sub(lgCopy, NewInt(1))

		if lg.Cmp(lgCopy) == 0 {
			t.Errorf("Int.DeepCopy: Copy not seperate from original, Expected: %v, Received: %v",
				lg.Text(16), lgCopy.Text(16))
		}
	}

}

////////////////////////////////////////////////////////////////////////////////
// Setters                                                                    //
////////////////////////////////////////////////////////////////////////////////

// TestSet checks if the modified Int is the same as the original
func TestSet(t *testing.T) {
	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	if actual.Cmp(expected) == 0 {
		t.Errorf("Original Ints should be different to test Set")
	}

	actual.Set(expected)

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of Set failed, expected: '0', got: '%v'",
			result)
	}
}

func TestSetBigInt(t *testing.T) {
	expectedBig := big.NewInt(int64(42))
	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	if actual.Cmp(expected) == 0 {
		t.Errorf("Original Ints should be different to test Set")
	}

	actual.SetBigInt(expectedBig)

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of SetBigInt failed, expected: '0', got: '%v'",
			result)
	}
}

// TestSetString checks if the modified Int is the same as the original
func TestSetString(t *testing.T) {
	type testStructure struct {
		str  string
		base int
	}

	testStructs := []testStructure{
		{"42", 0},
		{"100000000", 0},
		{"-5", 0},
		{"0", 0},
		{"f", 0},
		{"182", 5},
		{"9000000000000000000000000000000090090909090909090090909090909090", 0},
		{"-1", 2},
	}

	expected := []*Int{
		NewInt(42),
		NewInt(100000000),
		NewInt(-5),
		NewInt(0),
		nil,
		nil,
		NewIntFromString("9000000000000000000000000000000090090909090909090090909090909090", 10),
		NewInt(-1),
	}
	actual := NewInt(0)

	for i, tt := range testStructs {
		actual, aSuccess := actual.SetString(tt.str, tt.base)

		// Test invalid input making sure it occurs when expected
		if aSuccess == false {
			if actual != nil && expected[i] == nil {
				t.Error("Test of SetString() failed at index:", i,
					"Function didn't handle invalid input correctly")
			}
		} else {
			if actual.Cmp(expected[i]) != 0 {
				t.Errorf("Test of SetString() failed at index: %v Expected: %v;"+
					" Actual: %v", i, expected[i], actual)
			}
		}
	}
}

// TestSetBytes
func TestSetBytes(t *testing.T) {
	expected := []*Int{
		NewInt(42),
		NewInt(6553522),
		NewIntFromString("867530918239450598372829049587", 10),
		NewInt(0)}
	testBytes := [][]byte{
		{0x2A},             // 42
		{0x63, 0xFF, 0xB2}, // 6553522
		{0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20,
			0x57, 0xCE, 0xF4, 0x32, 0xF3}, // "867530918239450598372829049587",
		{0x00}}

	actual := NewInt(0)
	for i, tt := range testBytes {
		actual = actual.SetBytes(tt)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of SetBytes failed at index %v, expected: '%v', "+
				"actual: %v", i, expected[i].Text(10), actual.Text(10))
		}
	}
}

// Checks whether you can set an Int correctly with an int64
func TestSetInt64(t *testing.T) {
	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	actual.SetInt64(expected.Int64())

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of SetInt64 failed, expected: '0', got: '%v'",
			result)
	}
}

// Checks whether you can set an Int correctly with a uint64
func TestSetUint64(t *testing.T) {
	expected := NewInt(int64(42))

	actual := NewInt(int64(69))

	actual.SetUint64(expected.Uint64())

	result := actual.Cmp(expected)

	if result != 0 {
		t.Errorf("Test of SetUint64 failed, expected: '0', got: '%v'",
			result)
	}
}

// This test will fail on 32-bit machines
// Tests that SetBits sets an integer
func TestInt_SetBits(t *testing.T) {
	expected := NewIntFromString("1245967457601407658012964425109124356120693", 10)
	actual := NewInt(int64(99))
	actual.SetBits(Bits{5168612429366960245, 10501165033672452302, 3661})

	if actual.Cmp(expected) != 0 {
		t.Errorf("expected %v, got %v", expected.Text(16), actual.Text(16))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Converters                                                                 //
////////////////////////////////////////////////////////////////////////////////

// BigInt converts the Int to a *big.Int representation
func TestBigInt(t *testing.T) {
	expected := big.NewInt(int64(42))
	actual := NewInt(int64(42)).BigInt()

	if actual.Cmp(expected) != 0 {
		t.Errorf("Test of BigInt failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

// TestInt64 checks if Int64 returns a valid int64 or nil according to value
func TestInt64(t *testing.T) {
	expected := int64(42)
	actual := NewInt(int64(42)).Int64()

	if actual != expected {
		t.Errorf("Test of Int64 failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

// TestUint64 checks if Uint64 returns a valid uint64 or nil according to value
func TestUint64(t *testing.T) {
	expected := uint64(42)
	actual := NewIntFromUInt(uint64(42)).Uint64()

	if actual != expected {
		t.Errorf("Test of Uint64 failed, expected: '%v', got: '%v'",
			expected, actual)
	}
}

// TestIsInt64
func TestIsInt64(t *testing.T) {
	testInts := []*Int{
		NewInt(0),
		NewInt(1000000),
		NewInt(9223372036854775807),
		NewInt(0), // int64 overflow test below
		NewInt(-1),
		NewInt(-9223372036854775808),
		NewInt(0), // int64 overflow test below
	}
	// int64 overflow tests
	success := false
	testInts[3], success = testInts[3].SetString("9223372036854775808", 10)
	if success == false {
		println("FAILED")
	}
	testInts[6], success = testInts[6].SetString("-9223372036854775809", 10)
	if success == false {
		println("FAILED")
	}
	expected := []bool{
		true,
		true,
		true,
		false,
		true,
		true,
		false,
	}
	for i, tt := range testInts {
		actual := tt.IsInt64()
		if actual != expected[i] {
			t.Errorf("Test of IsInt64 failed at index %v, expected: '%v', "+
				"actual: %v", i, expected[i], actual)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Basic Arithmetic Operators                                                 //
////////////////////////////////////////////////////////////////////////////////

// TestAdd checks if the Add function returns correct results
func TestAdd(t *testing.T) {
	type testStructure struct{ x, y, z *Int }
	testCases := []testStructure{
		{NewInt(42), NewInt(69), NewInt(30)},
		{NewInt(0), NewInt(69), NewInt(0)},
		{NewInt(-50), NewInt(69), NewInt(10000)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30)},
	}
	expected := []*Int{NewInt(111), NewInt(69), NewInt(19), NewInt(0)}
	expected[3].SetString("9223372036854775817", 10)

	for i, tt := range testCases {
		actual := tt.z.Add(tt.x, tt.y)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of Add() failed at index: %v Expected: %v; Actual: %v",
				i, expected[i].Text(10), actual.Text(10))
		}
	}
}

// TestSub checks if the Sub function returns the correct result
func TestSub(t *testing.T) {

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
		{"42", "42", "0"},
		{"42", "69", "-27"},
		{"69", "42", "27"},
		{"-69", "42", "-111"},
		{"-69", "-42", "-27"},
		{"1000000000", "1000000000", "0"},
		{"1000000000", "9999999999999999999999", "-9999999999998999999999"},
		{"9999999999999999999999", "1000000000", "9999999999998999999999"},
	}

	var testStructs []testStructure

	var success bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, success = NewInt(0).SetString(strs[0], 10)

		if success != true {
			t.Errorf("Setup for Test of Sub() failed at 'x' phase of index: %v", i)
		}

		ts.y, success = NewInt(0).SetString(strs[1], 10)

		if success != true {
			t.Errorf("Setup for Test of Sub() failed at 'y' phase of index: %v", i)
		}

		ts.z, success = NewInt(0).SetString(strs[2], 10)

		if success != true {
			t.Errorf("Setup for Test of Sub() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}
	expected := 0

	for i, tt := range testStructs {
		actual := NewInt(0).Sub(tt.x, tt.y)

		result := actual.Cmp(tt.z)

		if result != expected {
			t.Errorf("Test of Sub() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, tt.z.Text(10), result, actual.Text(10))
		}
	}

}

// TestAdd checks if the Mul function returns correct results
func TestMul(t *testing.T) {
	type testStructure struct{ x, y, z *Int }
	testCases := []testStructure{
		{NewInt(42), NewInt(69), NewInt(30)},
		{NewInt(0), NewInt(69), NewInt(0)},
		{NewInt(-50), NewInt(69), NewInt(10000)},
		{NewInt(9223372036854775807), NewInt(10), NewInt(30)},
	}
	expected := []*Int{NewInt(2898), NewInt(0), NewInt(-3450), NewInt(0)}
	expected[3].SetString("92233720368547758070", 10)

	for i, tt := range testCases {
		actual := tt.z.Mul(tt.x, tt.y)
		if actual.Cmp(expected[i]) != 0 {
			t.Errorf("Test of Mul() failed at index: %v Expected: %v; Actual: %v",
				i, expected[i].Text(10), actual.Text(10))
		}
	}
}

// TestDiv checks if the Sub function returns the correct result
func TestDiv(t *testing.T) {

	type testStructure struct {
		x *Int
		y *Int
		z *Int
	}

	testStrings := [][]string{
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

	var testStructs []testStructure

	var success bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, success = NewInt(0).SetString(strs[0], 10)

		if success != true {
			t.Errorf("Setup for Test of Div() failed at 'x' phase of index: %v", i)
		}

		ts.y, success = NewInt(0).SetString(strs[1], 10)

		if success != true {
			t.Errorf("Setup for Test of Div() failed at 'y' phase of index: %v", i)
		}

		ts.z, success = NewInt(0).SetString(strs[2], 10)

		if success != true {
			t.Errorf("Setup for Test of Div() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}
	expected := 0

	for i, tt := range testStructs {
		actual := NewInt(0).Div(tt.x, tt.y)

		result := actual.Cmp(tt.z)

		if result != expected {
			t.Errorf("Test of Div() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, tt.z.Text(10), result, actual.Text(10))
		}
	}

}

////////////////////////////////////////////////////////////////////////////////
// Operators with Modulo                                                      //
////////////////////////////////////////////////////////////////////////////////

// TestMod checks if the Mod operation returns the correct result
func TestMod(t *testing.T) {

	type testStructure struct {
		x *Int
		m *Int
		r *Int
	}

	testStrings := [][]string{
		{"42", "42", "0"},
		{"42", "69", "42"},
		{"69", "42", "27"},
		{"1000000000", "11", "10"},
		{"1000000000", "9999999999999999999999", "1000000000"},
		{"9999999999999999999999", "10000", "9999"},
	}

	var testStructs []testStructure

	var success bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, success = NewInt(0).SetString(strs[0], 10)

		if success != true {
			t.Errorf("Setup for Test of Mod() failed at 'x' phase of index: %v", i)
		}

		ts.m, success = NewInt(0).SetString(strs[1], 10)

		if success != true {
			t.Errorf("Setup for Test of Mod() failed at 'm' phase of index: %v", i)
		}

		ts.r, success = NewInt(0).SetString(strs[2], 10)

		if success != true {
			t.Errorf("Setup for Test of Mod() failed at 'r' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}
	expected := 0

	for i, tt := range testStructs {
		actual := NewInt(0).Mod(tt.x, tt.m)

		result := actual.Cmp(tt.r)

		if result != expected {
			t.Errorf("Test of Mod() failed at index: %v Expected: %v, %v;"+
				" Actual: %v, %v", i, expected, tt.r.Text(10), result, actual.Text(10))
		}
	}

}

// TestModInverse checks if the ModInverse returns the correct result
func TestModInverse(t *testing.T) {
	type testStructure struct {
		z *Int
		m *Int
	}

	int1 := NewInt(1)

	testStrings := [][]string{
		{"3", "11"},
		{"42", "11"},
		{"100000", "15487469"},
	}

	var testStructs []testStructure

	var success bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.z, success = NewInt(0).SetString(strs[0], 10)

		if success != true {
			t.Errorf("Setup for Test of ModInverse() failed at 'z' phase of index: %v", i)
		}

		ts.m, success = NewInt(0).SetString(strs[1], 10)

		if success != true {
			t.Errorf("Setup for Test of ModInverse() failed at 'm' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}

	expected := 0

	for i, tt := range testStructs {
		actual := NewInt(0).ModInverse(tt.z, tt.m)

		reMultiply := NewInt(0).Mul(tt.z, actual)

		reMultiply = reMultiply.Mod(reMultiply, tt.m)

		result := int1.Cmp(reMultiply)

		if result != expected {
			t.Errorf("Test of ModInverse() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, int1.Text(10), result, reMultiply.Text(10))
		}
	}

}

// Tests that the ModInverse function returns nil when no inverse can be found
func TestModInverse_Fail(t *testing.T) {

	p := NewInt(100)
	a := NewInt(20)
	b := NewInt(1)
	rtn := b.ModInverse(a, p)

	if rtn != nil {
		t.Errorf("ModInverse() did not fail with invalid input")
	}
}

// TestExp checks if Int.Exp returns the correct results.
func TestExp(t *testing.T) {
	type testStructure struct{ x, y, m, z *Int }
	testStrings := [][]string{
		{"42", "42", "11", "4"},
		{"42", "69", "31", "23"},
		{"-69", "42", "17", "1"},
		{"1000000000", "9999999", "12432332443", "6589464193"},
	}
	var testStructs []testStructure

	var success bool

	for i, strs := range testStrings {
		var ts testStructure

		ts.x, success = NewInt(0).SetString(strs[0], 10)

		if success != true {
			t.Errorf("Setup for Test of Exp() failed at 'x' phase of index: %v", i)
		}

		ts.y, success = NewInt(0).SetString(strs[1], 10)

		if success != true {
			t.Errorf("Setup for Test of Exp() failed at 'y' phase of index: %v", i)
		}

		ts.m, success = NewInt(0).SetString(strs[2], 10)

		if success != true {
			t.Errorf("Setup for Test of Exp() failed at 'm' phase of index: %v", i)
		}

		ts.z, success = NewInt(0).SetString(strs[3], 10)

		if success != true {
			t.Errorf("Setup for Test of Exp() failed at 'z' phase of index: %v", i)
		}

		testStructs = append(testStructs, ts)
	}
	expected := 0

	for i, tt := range testStructs {
		actual := NewInt(0).Exp(tt.x, tt.y, tt.m)

		result := actual.Cmp(tt.z)

		if result != expected {
			t.Errorf("Test of Exp() failed at index: %v Expected: %v, %v; Actual: %v, %v",
				i, expected, tt.z.Text(10), result, actual.Text(10))
		}
	}

}

////////////////////////////////////////////////////////////////////////////////
// GCD Operator                                                               //
////////////////////////////////////////////////////////////////////////////////

func TestGCD(t *testing.T) {
	a := NewInt(178919)
	b := NewInt(987642)
	// These will be filled in by GCD and can calculate modular inverse
	x := NewInt(0)
	y := NewInt(0)
	// This will hold the actual GCD
	actual := NewInt(0)

	actual.GCD(x, y, a, b)

	expected := NewInt(1)

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestGCD: got %v, expected %v", actual.Text(10),
			expected.Text(10))
	}
	// use results of extended GCD to calculate modular inverse and check
	// consistency with ModInverse
	if x.Cmp(NewInt(0)) < 0 {
		// we need to add the prime in again to put the result back in the
		// group
		x.Add(x, b)
	}
	modInverseResult := NewInt(0)
	if x.Cmp(modInverseResult.ModInverse(a, b)) != 0 {
		t.Errorf("TestGCD: got incorrect modular inverse %v, "+
			"expected %v", x.Text(10), modInverseResult.Text(10))
	}
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous Operators                                                    //
////////////////////////////////////////////////////////////////////////////////

// Test that IsCoprime returns false when sent a 0
func TestIsCoprime0(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(0)
	if a.IsCoprime(b) {
		t.Errorf("0 cannot be Coprime!")
	}
}

// Test that IsCoprime returns true when sent a 1
func TestIsCoprime1(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(1)
	if !a.IsCoprime(b) {
		t.Errorf("1 must always be Coprime")
	}
}

// Test that IsCoprime returns true when sent a 14
func TestIsCoprime49(t *testing.T) {
	a := NewInt(50580)
	b := NewInt(49)
	if !a.IsCoprime(b) {
		gcdAB := NewInt(0)
		gcdAB.GCD(nil, nil, a, b)
		t.Errorf("49 must always be Coprime: GCD(%d, %d) -> %d)",
			a.Int64(), b.Int64(), gcdAB.Int64())
	}
}

func TestIsPrime(t *testing.T) {
	n := NewInt(101) // 101 is prime
	if !n.IsPrime() {
		t.Errorf("IsPrime: %v should be prime!", n.Uint64())
	}

	n = NewInt(63) // 63 is NOT prime
	if n.IsPrime() {
		t.Errorf("IsPrime: %v should NOT be prime!", n.Uint64())
	}
}

// TestBitLen checks if the BitLen placeholder exists
func TestBitLen(t *testing.T) {
	testInts := []*Int{NewInt(42), NewInt(6553522), NewInt(0), NewInt(-42)}
	testInts[2], _ = testInts[2].SetString("867530918239450598372829049587", 10)
	expectedLens := []int{6, 23, 100, 6}

	for i, tt := range testInts {
		actual := tt.BitLen()
		if actual != expectedLens[i] {
			t.Errorf("Case %v of BitLen failed, got: '%v', expected: '%v'", i, actual,
				expectedLens[i])
		}
	}
}

// TestByteLen checks if the ByteLen placeholder exists
func TestByteLen(t *testing.T) {
	testInts := []*Int{
		NewInt(2),       // 2 bits  -->  1 bytes (where +6 works)
		NewInt(8388608), // 24 bits -->  3 bytes (exactly)
		NewInt(0),       // 1 bit   -->  1 byte  (irrelevant b/c it's overwritten before testing)
		NewInt(-42)}     // 6 bits  -->  1 byte

	// Overwrites the value 0:    100 bits -->  13 bytes (where +4 works)
	testInts[2], _ = testInts[2].SetString("867530918239450598372829049587", 10)
	expectedLens := []int{1, 3, 13, 1}

	for i, tt := range testInts {
		actual := tt.ByteLen()
		if actual != expectedLens[i] {
			t.Errorf("Case %v of BitLen failed, got: '%v', expected: '%v'", i, actual,
				expectedLens[i])
		}
	}
}

// TestCmp checks if the Cmp placeholder exists
func TestCmp(t *testing.T) {

	var expected, actual int
	var x, y *Int

	// Tests for case where x < y

	expected = -1

	x = NewInt(42)
	y = NewInt(69)

	actual = x.Cmp(y)

	if actual != expected {
		t.Errorf("Test 'less than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	}

	// Tests for case where x==y

	expected = 0

	x = NewInt(42)
	y = NewInt(42)

	actual = x.Cmp(y)

	if actual != expected {
		t.Errorf("Test 'equals' of Cmp failed, expected: '%v', got: '%v'",
			actual, expected)
	}

	// Test for case where x > y

	expected = 1

	x = NewInt(69)
	y = NewInt(42)

	actual = x.Cmp(y)

	if actual != expected {
		t.Errorf("Test 'greater than' of Cmp failed, expected: '%v', got:"+
			" '%v'", actual, expected)
	}

}

////////////////////////////////////////////////////////////////////////////////
// Bitwise Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

func TestRightShift(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()

		shift := rng.Uint64() % 63

		value := NewIntFromUInt(aInt)

		actual := NewInt(0).RightShift(value, uint(shift))

		if actual.Uint64() != (aInt >> shift) {
			t.Errorf("Int.RightShift: shifted value not as expected: Expected: %v, Received: %v",
				aInt>>shift, actual.Uint64())
		}
	}

}

func TestLeftShift(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()

		shift := rng.Uint64() % 63

		value := NewIntFromUInt(aInt)

		actual := NewInt(0).LeftShift(value, uint(shift))

		if actual.Uint64() != (aInt << shift) {
			t.Errorf("Int.LeftShift: shifted value not as expected: Expected: %v, Received: %v",
				aInt<<shift, actual.Uint64())
		}
	}

}

func TestOr(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		val1 := NewIntFromUInt(aInt)
		val2 := NewIntFromUInt(bInt)

		actual := NewInt(0).Or(val1, val2)

		if actual.Uint64() != (aInt | bInt) {
			t.Errorf("Int.Or: ored value not as expected: Expected: %v, Received: %v",
				aInt|bInt, actual.Uint64())
		}
	}
}

func TestXor(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		val1 := NewIntFromUInt(aInt)
		val2 := NewIntFromUInt(bInt)

		actual := NewInt(0).Xor(val1, val2)

		if actual.Uint64() != (aInt ^ bInt) {
			t.Errorf("Int.Xor: xored value not as expected: Expected: %v, Received: %v",
				aInt^bInt, actual.Uint64())
		}
	}
}

func TestAnd(t *testing.T) {
	src := rand.NewSource(42)
	rng := rand.New(src)

	for i := 0; i < 100; i++ {
		aInt := rng.Uint64()
		bInt := rng.Uint64()

		val1 := NewIntFromUInt(aInt)
		val2 := NewIntFromUInt(bInt)

		actual := NewInt(0).And(val1, val2)

		if actual.Uint64() != (aInt & bInt) {
			t.Errorf("Int.And: andd value not as expected: Expected: %v, Received: %v",
				aInt&bInt, actual.Uint64())
		}
	}
}

func BenchmarkXor(b *testing.B) {
	src := rand.NewSource(42)
	rng := rand.New(src)
	var val1 []*Int
	var val2 []*Int

	for i := 0; i < b.N; i++ {
		byteField := make([]byte, 256)
		rng.Read(byteField)
		val1 = append(val1, NewIntFromBytes(byteField))
		rng.Read(byteField)
		val2 = append(val2, NewIntFromBytes(byteField))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewInt(0).Xor(val1[i], val2[i])
	}
}

////////////////////////////////////////////////////////////////////////////////
// Byte Slice Getters                                                         //
////////////////////////////////////////////////////////////////////////////////

// TestBytes checks if the Bytes placeholder exists
func TestBytes(t *testing.T) {
	testInts := []*Int{
		NewInt(42),
		NewInt(6553522),
		// *NewInt(867530918239450598372829049587), TODO: When text parsing impl
		NewInt(-42)}
	expectedBytes := [][]byte{
		{0x2A},             // 42
		{0x63, 0xFF, 0xB2}, // 6553522
		// { 0xA, 0xF3, 0x24, 0xC1, 0xA0, 0xAD, 0x87, 0x20,
		//   0x57, 0xCE, 0xF4, 0x32, 0xF3 }, //"867530918239450598372829049587",
		{0x2A}} // TODO: Should be <nil>, not 42

	for i, tt := range testInts {
		actual := tt.Bytes()
		for j, ttt := range expectedBytes[i] {
			if actual[j] != ttt {
				t.Errorf("Case %v of Text failed, got: '%v', expected: '%v'", i, actual,
					ttt)
			}
		}
	}
}

// TestLeftpadBytes makes sure that LeftpadBytes returns the correctly
// leftpadded byte strings
func TestLeftpadBytes(t *testing.T) {
	testInts := []*Int{NewInt(420), NewInt(6553522), NewInt(0), NewInt(-42)}
	testLengths := []uint64{3, 7, 5, 8}
	expected := [][]byte{{0, 1, 164}, {0, 0, 0, 0, 99, 255, 178},
		{0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 42}}

	for i := range testInts {
		actual := testInts[i].LeftpadBytes(testLengths[i])
		if !bytes.Equal(actual, expected[i]) {
			t.Errorf("LeftpadBytes: Actual differed from expected at index"+
				" %v. Got %v, expected %v.", i, actual, expected[i])
		}
	}
}

// TestLeftpadBytes_Panic makes sure that the function panics when the
// requested length is smaller than the actual length of the Int
func TestLeftpadBytes_Panic(t *testing.T) {
	testVal := NewInt(6553522)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("LeftpadBytes should panic on length < byteLen(num)!")
		}
	}()

	testVal.LeftpadBytes(2)
}

////////////////////////////////////////////////////////////////////////////////
// String Representation Getters                                              //
////////////////////////////////////////////////////////////////////////////////

// TestText checks if the Text placeholder exists
func TestText(t *testing.T) {
	testInts := []*Int{
		NewInt(42),
		NewInt(6553522),
		NewIntFromString("867530918239450598372829049587", 10),
		NewInt(-42)}
	expectedStrings := []string{
		"42",
		"6553522",
		"8675309182...",
		"-42"} // TODO: Should be <nil>, not -42

	for i, tt := range testInts {
		actual := tt.Text(10)
		expected := expectedStrings[i]
		if actual != expected {
			t.Errorf("Test of Text failed, got: '%v', expected: '%v'", actual,
				expected)
		}
	}
}

func TestTextVerbose(t *testing.T) {
	testInt := NewIntFromString("867530918239450598372829049587", 10)
	lens := []int{12, 16, 18, 0}
	expected := []string{"867530918239...", "8675309182394505...",
		"867530918239450598...", "867530918239450598372829049587"}
	for i, testLen := range lens {
		actual := testInt.TextVerbose(10, testLen)
		if actual != expected[i] {
			t.Errorf("Test of TextVerbose failed, got: %v,"+
				"expected: %v", actual, expected[i])
		}
	}
}

func TestInt_Bits(t *testing.T) {
	testInt := NewIntFromString("867530918239450598372829049587", 10)
	actual := testInt.Bits()
	expected := Bits{12503998451923825395, 47028945312}
	for i := 0; i < len(actual); i++ {
		if actual[i] != expected[i] {
			t.Errorf("Bits differed at index %v. Got %v, expected %v", i, actual[i], expected[i])
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// GOB Operators                                                              //
////////////////////////////////////////////////////////////////////////////////

func TestGob(t *testing.T) {

	var byteBuf bytes.Buffer

	enc := gob.NewEncoder(&byteBuf)
	dec := gob.NewDecoder(&byteBuf)

	inInt := NewInt(42)

	_ = enc.Encode(inInt)

	outInt := NewInt(0)

	_ = dec.Decode(&outInt)

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("GobEncoder/GobDecoder failed, "+
			"Expected: %v; Received: %v ", inInt.Text(10), outInt.Text(10))
	}

}

////////////////////////////////////////////////////////////////////////////////
// Marshal Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

// Happy path.
func TestInt_MarshalJSON_UnmarshalJSON(t *testing.T) {
	inInt := NewInt(42)

	data, err := inInt.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON() produced an error: %+v", err)
	}
	outInt := NewInt(0)
	err = outInt.UnmarshalJSON(data)
	if err != nil {
		t.Errorf("UnmarshalJSON() produced an error: %+v", err)
	}

	if inInt.Cmp(outInt) != 0 {
		t.Errorf("Failed to marshal and unmarshal Int."+
			"\n\texpected: %s\n\treceived: %s", inInt.Text(10), outInt.Text(10))
	}
}

// Error path: json data does not contain int data.
func TestInt_UnmarshalJSON_InvalidIntError(t *testing.T) {
	outInt := NewInt(0)
	err := outInt.UnmarshalJSON([]byte("\"abc\""))
	if err == nil {
		t.Errorf("UnmarshalJSON() did not produce an error for invalid Int data.")
	}

	if outInt.Cmp(NewInt(0)) != 0 {
		t.Errorf("Failed to marshal and unmarshal Int."+
			"\n\texpected: %s\n\treceived: %s", outInt.Text(10), NewInt(0).Text(10))
	}
}
