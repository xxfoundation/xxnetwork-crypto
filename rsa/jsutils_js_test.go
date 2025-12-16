////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package rsa

import (
	"bytes"
	"syscall/js"
	"testing"
)

// Test_copyBytesToJS_copyBytesToGo verifies round-trip conversion.
func Test_copyBytesToJS_copyBytesToGo(t *testing.T) {
	testCases := [][]byte{
		{},
		{0},
		{1, 2, 3, 4, 5},
		make([]byte, 1024), // larger buffer
	}

	for i, original := range testCases {
		jsVal := copyBytesToJS(original)

		// Verify it's a Uint8Array with correct length
		if jsVal.Length() != len(original) {
			t.Errorf("Case %d: length mismatch: expected %d, got %d",
				i, len(original), jsVal.Length())
		}

		// Round-trip back to Go
		result := copyBytesToGo(jsVal)
		if !bytes.Equal(original, result) {
			t.Errorf("Case %d: round-trip failed:\noriginal: %v\nresult: %v",
				i, original, result)
		}
	}
}

// Test_uint8Array verifies the Uint8Array constructor is valid.
func Test_uint8Array(t *testing.T) {
	if uint8Array.IsUndefined() {
		t.Fatal("uint8Array is undefined")
	}

	// Create a new Uint8Array
	arr := uint8Array.New(10)
	if arr.Length() != 10 {
		t.Errorf("Expected length 10, got %d", arr.Length())
	}
}

// Test_await_resolve verifies await handles resolved promises.
func Test_await_resolve(t *testing.T) {
	// Create a promise that resolves with a value
	promiseConstructor := js.Global().Get("Promise")

	var resolveFunc js.Func
	resolveFunc = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]
		resolve.Invoke("test value")
		return nil
	})
	defer resolveFunc.Release()

	promise := promiseConstructor.New(resolveFunc)

	results, errs := await(promise)
	if errs != nil {
		t.Fatalf("Expected no error, got: %v", errs)
	}
	if len(results) != 1 || results[0].String() != "test value" {
		t.Errorf("Expected 'test value', got: %v", results)
	}
}

// Test_await_reject verifies await handles rejected promises.
func Test_await_reject(t *testing.T) {
	promiseConstructor := js.Global().Get("Promise")

	var rejectFunc js.Func
	rejectFunc = js.FuncOf(func(_ js.Value, args []js.Value) any {
		reject := args[1]
		reject.Invoke("error reason")
		return nil
	})
	defer rejectFunc.Release()

	promise := promiseConstructor.New(rejectFunc)

	results, errs := await(promise)
	if results != nil {
		t.Fatalf("Expected no result, got: %v", results)
	}
	if len(errs) != 1 || errs[0].String() != "error reason" {
		t.Errorf("Expected 'error reason', got: %v", errs)
	}
}
