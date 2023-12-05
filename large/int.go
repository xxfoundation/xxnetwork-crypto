////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package large

import (
	"fmt"
	"math/big"

	jww "github.com/spf13/jwalterweatherman"
)

// Int extends Go's big.Int structure
type Int big.Int

// Bits is a slice of words. It can be used to access underlying word array for
// faster CUDA staging.
type Bits []big.Word

////////////////////////////////////////////////////////////////////////////////
// Constructors                                                               //
////////////////////////////////////////////////////////////////////////////////

// NewInt allocates and returns a new Int set to x.
func NewInt(x int64) *Int {
	s := new(Int)
	*s = Int(*big.NewInt(x))
	return s
}

// NewIntFromBytes creates a new Int initialized from a byte buffer.
func NewIntFromBytes(buf []byte) *Int {
	s := new(Int)
	s.SetBytes(buf)
	return s
}

// NewIntFromString creates a new Int from a string using the passed in base.
// Returns nil if str cannot be parsed.
func NewIntFromString(str string, base int) *Int {
	s := new(Int)
	_, b := s.SetString(str, base)
	if !b {
		return nil
	}
	return s
}

// NewIntFromBigInt allocates and returns a new Int from a big.Int.
func NewIntFromBigInt(x *big.Int) *Int {
	s := new(Int)
	s.SetBigInt(x)
	return s
}

// NewMaxInt creates a new Int with the value Max4kBitInt.
func NewMaxInt() *Int {
	return NewIntFromBytes(Max4kBitInt)
}

// NewIntFromUInt creates a new Int from a uint64.
func NewIntFromUInt(i uint64) *Int {
	s := new(Int)
	s.SetUint64(i)
	return s
}

// NewIntFromBits creates a new Int from a Bits.
func NewIntFromBits(b Bits) *Int {
	s := new(Int)
	s.SetBits(b)
	return s
}

// DeepCopy creates a deep copy of the Int.
func (z *Int) DeepCopy() *Int {
	return NewInt(0).Set(z)
}

////////////////////////////////////////////////////////////////////////////////
// Setters                                                                    //
////////////////////////////////////////////////////////////////////////////////

// Set sets z to x and returns z.
func (z *Int) Set(x *Int) *Int {
	(*big.Int)(z).Set((*big.Int)(x))
	return z
}

// SetBigInt sets z to big.Int x and returns z.
func (z *Int) SetBigInt(x *big.Int) *Int {
	(*big.Int)(z).Set(x)
	return z
}

// SetString makes the Int equal to the number held in the string s, interpreted
// to have a base of b. Returns the set Int and a boolean describing if the
// operation was successful.
func (z *Int) SetString(s string, base int) (*Int, bool) {
	y := (*big.Int)(z)
	_, b := y.SetString(s, base)
	if !b {
		return nil, false
	}
	return z, b
}

// SetBytes interprets buf as the bytes of a big-endian unsigned integer, sets z
// to that value, and returns z.
func (z *Int) SetBytes(buf []byte) *Int {
	(*big.Int)(z).SetBytes(buf)
	return z
}

// SetInt64 sets z to the value of the passed int64.
func (z *Int) SetInt64(x int64) *Int {
	(*big.Int)(z).SetInt64(x)
	return z
}

// SetUint64 sets z to the value of the passed uint64.
func (z *Int) SetUint64(x uint64) *Int {
	(*big.Int)(z).SetUint64(x)
	return z
}

// SetBits sets z to the passed Bits.
func (z *Int) SetBits(x Bits) *Int {
	(*big.Int)(z).SetBits(x)
	return z
}

////////////////////////////////////////////////////////////////////////////////
// Converters                                                                 //
////////////////////////////////////////////////////////////////////////////////

// BigInt converts the Int to a *big.Int representation.
func (z *Int) BigInt() *big.Int {
	return (*big.Int)(z)
}

// Int64 converts the Int to an int64, if possible, or undefined result if not
// possible.
func (z *Int) Int64() int64 {
	return (*big.Int)(z).Int64()
}

// Uint64 converts the Int to a uint64, if possible, or undefined result if not
// possible.
func (z *Int) Uint64() uint64 {
	return (*big.Int)(z).Uint64()
}

// IsInt64 checks if an Int can be converted to an int64.
func (z *Int) IsInt64() bool {
	return (*big.Int)(z).IsInt64()
}

////////////////////////////////////////////////////////////////////////////////
// Basic Arithmetic Operators                                                 //
////////////////////////////////////////////////////////////////////////////////

// Add sets z to the sum x+y and returns z.
func (z *Int) Add(x, y *Int) *Int {
	(*big.Int)(z).Add(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Sub sets z to the difference x-y and returns z.
func (z *Int) Sub(x, y *Int) *Int {
	(*big.Int)(z).Sub(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Mul sets z to the product x*y and returns z.
func (z *Int) Mul(x, y *Int) *Int {
	(*big.Int)(z).Mul(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Div sets z to the quotient x/y and returns z.
func (z *Int) Div(x, y *Int) *Int {
	(*big.Int)(z).Div(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

////////////////////////////////////////////////////////////////////////////////
// Operators with Modulo                                                      //
////////////////////////////////////////////////////////////////////////////////

// Mod sets z to the modulus x%y for y != 0 and returns z. If y == 0, a
// division-by-zero run-time panic occurs. Mod implements Euclidean modulus
// (unlike Go); see DivMod for more details.
func (z *Int) Mod(x, y *Int) *Int {
	(*big.Int)(z).Mod(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// ModInverse sets z to the multiplicative inverse of x in the ring ℤ/nℤ and
// returns z. If x and n are not relatively prime, g has no multiplicative
// inverse in the ring ℤ/nℤ. In this case, z is unchanged and the return value
// is nil. If n == 0, then a division-by-zero run-time panic occurs.
func (z *Int) ModInverse(x, n *Int) *Int {
	return (*Int)((*big.Int)(z).ModInverse(
		(*big.Int)(x),
		(*big.Int)(n)))
}

// Exp sets z = x**y mod |m| (i.e. the sign of m is ignored), and returns z. If
// y <= 0, then the result is 1 mod |m|; if m == nil or m == 0, then z = x**y.
//
// Modular exponentiation of inputs of a particular size is not a
// cryptographically constant-time operation.
func (z *Int) Exp(x, y, m *Int) *Int {
	(*big.Int)(z).Exp(
		(*big.Int)(x),
		(*big.Int)(y),
		(*big.Int)(m))
	return z
}

////////////////////////////////////////////////////////////////////////////////
// GCD Operator                                                               //
////////////////////////////////////////////////////////////////////////////////

// GCD sets z to the greatest common divisor of a and b and returns z. If x or y
// are not nil, GCD sets their value such that z = a*x + b*y.
func (z *Int) GCD(x, y, a, b *Int) *Int {
	(*big.Int)(z).GCD(
		(*big.Int)(x),
		(*big.Int)(y),
		(*big.Int)(a),
		(*big.Int)(b))
	return z
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous Operator                                                     //
////////////////////////////////////////////////////////////////////////////////

// IsCoprime returns true if the two numbers are coprime (relatively prime).
func (z *Int) IsCoprime(x *Int) bool {
	s := NewInt(0)
	return s.ModInverse(z, x) != nil
}

// FillBytes sets buf to the absolute value of x, storing it as a zero-extended
// big-endian byte slice, and returns buf.
//
// If the absolute value of x does not fit in buf, then FillBytes will panic.
func (z *Int) FillBytes(buf []byte) []byte {
	return (*big.Int)(z).FillBytes(buf)
}

// IsPrime calculates (with high probability) if a number is prime or not.
// This function uses 40 (can be changed) iterations of the Miller-Rabin prime
// test. Returns true if number is prime and false if it is not.
func (z *Int) IsPrime() bool {
	return (*big.Int)(z).ProbablyPrime(40)
}

// BitLen returns the length of the absolute value of z, in bits. The bit length
// of 0 is 0.
func (z *Int) BitLen() int {
	return (*big.Int)(z).BitLen()
}

// ByteLen returns the length of the absolute value of z, in bytes.
func (z *Int) ByteLen() int {
	byteLen := ((*big.Int)(z).BitLen() + 7) / 8
	return byteLen
}

// Cmp compares x and y and returns:
//
//	-1 if x < y
//	 0 if x == y
//	+1 if x > y
func (z *Int) Cmp(y *Int) int {
	return (*big.Int)(z).Cmp((*big.Int)(y))
}

////////////////////////////////////////////////////////////////////////////////
// Bitwise Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

// RightShift shifts the value right by n bits.
func (z *Int) RightShift(x *Int, n uint) *Int {
	(*big.Int)(z).Rsh((*big.Int)(x), n)
	return z
}

// LeftShift shifts the value left by n bits.
func (z *Int) LeftShift(x *Int, n uint) *Int {
	(*big.Int)(z).Lsh((*big.Int)(x), n)
	return z
}

// Or computes the bitwise or operation between x and y.
func (z *Int) Or(x, y *Int) *Int {
	(*big.Int)(z).Or(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// Xor computes the bitwise xor operation between the x and y.
func (z *Int) Xor(x, y *Int) *Int {
	(*big.Int)(z).Xor(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

// And computes the bitwise and operation between x and y.
func (z *Int) And(x, y *Int) *Int {
	(*big.Int)(z).And(
		(*big.Int)(x),
		(*big.Int)(y))
	return z
}

////////////////////////////////////////////////////////////////////////////////
// Byte Slice Getters                                                         //
////////////////////////////////////////////////////////////////////////////////

// Bytes returns the absolute value of x as a big-endian byte slice.
func (z *Int) Bytes() []byte {
	return (*big.Int)(z).Bytes()
}

// LeftpadBytes returns the absolute value of x left-padded with zeroes up to
// the passed number of bytes. Panics if the byte slice from the Int is longer
// than the passed length.
func (z *Int) LeftpadBytes(length uint64) []byte {
	b := z.Bytes()

	if uint64(len(b)) > length {
		jww.FATAL.Panicf("large.Int.LeftpadBytes(): Byte array too long! "+
			"Expected: %d, Received: %d", length, len(b))
	}

	leftPaddedBytes := make([]byte, length-uint64(len(b)))
	leftPaddedBytes = append(leftPaddedBytes, b...)

	return leftPaddedBytes
}

// Bits returns the underlying big.Int word slice. This is used for copying to
// gpumaths input.
func (z *Int) Bits() Bits {
	return (*big.Int)(z).Bits()
}

////////////////////////////////////////////////////////////////////////////////
// String Representation Getters                                              //
////////////////////////////////////////////////////////////////////////////////

// Text returns the string representation of z in the given base. Base must be
// between 2 and 36, inclusive. The result uses the lower-case letters 'a' to
// 'z' for digit values >= 10. No base prefix (such as "0x") is added to the
// string.
//
// Text truncates the Int to a length of 10, appending an ellipsis if the Int is
// too long.
func (z *Int) Text(base int) string {
	const intTextLen = 10
	return z.TextVerbose(base, intTextLen)
}

// TextVerbose returns the string representation of z in the given base. Base
// must be between 2 and 36, inclusive. The result uses the lower-case letters
// 'a' to 'z' for digit values >= 10. No base prefix (such as "0x") is added to
// the string.
//
// TextVerbose truncates the Int to a length of length in characters (not runes)
// and appends an ellipsis to indicate that the whole int wasn't returned,
// unless len is 0, in which case it will return the whole int as a string.
func (z *Int) TextVerbose(base int, length int) string {
	fullText := (*big.Int)(z).Text(base)

	if length == 0 || len(fullText) <= length {
		return fullText
	} else {
		return fullText[:length] + "..."
	}
}

////////////////////////////////////////////////////////////////////////////////
// GOB Operators                                                              //
////////////////////////////////////////////////////////////////////////////////

// GobDecode decodes the byte slice into an Int. Error is always nil.
// This function implements the gob.GobDecoder interface.
func (z *Int) GobDecode(in []byte) error {
	z.SetBytes(in)
	return nil
}

// GobEncode encodes the Int into a byte slice. Error is always nil.
// This function implements the gob.GobEncoder interface.
func (z *Int) GobEncode() ([]byte, error) {
	return z.Bytes(), nil
}

////////////////////////////////////////////////////////////////////////////////
// Marshal Operators                                                          //
////////////////////////////////////////////////////////////////////////////////

// MarshalJSON implements the json.Marshaler interface.
func (z *Int) MarshalJSON() ([]byte, error) {
	bigInt := big.Int(*z)
	return bigInt.MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (z *Int) UnmarshalJSON(b []byte) error {
	bigInt := big.Int(*z)
	err := bigInt.UnmarshalJSON(b)
	if err != nil {
		return err
	}
	*z = (Int)(bigInt)
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Constants                                                                  //
////////////////////////////////////////////////////////////////////////////////

// Max4kBitInt is a 4128-bit int that is meant to be the size of post mod-ed
// large ints.
//
// It will probably be made to hold this 4096 bit prime:
// https://tools.ietf.org/html/rfc3526#page-5
var Max4kBitInt = []byte{
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

// Format implements fmt.Formatter. It accepts the formats
// 'b' (binary), 'o' (octal with 0 prefix), 'O' (octal with 0o prefix),
// 'd' (decimal), 'x' (lowercase hexadecimal), and 'X' (uppercase hexadecimal).
//
// Also supported are the full suite of package fmt's format flags for integral
// types, including '+' and ' ' for sign control, '#' for leading zero in octal
// and for hexadecimal, a leading "0x" or "0X" for "%#x" and "%#X" respectively,
// specification of minimum digit precision, output field width, space or zero
// padding, and '-' for left or right justification.
func (z *Int) Format(s fmt.State, ch rune) {
	(*big.Int)(z).Format(s, ch)
}
