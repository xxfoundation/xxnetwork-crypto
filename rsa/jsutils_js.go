////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package rsa

import "syscall/js"

var uint8Array = js.Global().Get("Uint8Array")

// copyBytesToJS copies a Go byte slice to a JavaScript Uint8Array.
func copyBytesToJS(b []byte) js.Value {
	arr := uint8Array.New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

// copyBytesToGo copies a JavaScript Uint8Array to a Go byte slice.
func copyBytesToGo(v js.Value) []byte {
	b := make([]byte, v.Length())
	js.CopyBytesToGo(b, v)
	return b
}

// await blocks until a JavaScript Promise resolves or rejects.
//
// Memory model note: js.Func must not be Released() until after the callback
// has completed. For blocking await, we block on the channel until the callback
// fires, then explicitly release both handlers.
func await(promise js.Value) ([]js.Value, []js.Value) {
	resCh := make(chan []js.Value, 1)
	errCh := make(chan []js.Value, 1)

	var onResolve, onReject js.Func

	onResolve = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resCh <- args
		return nil
	})

	onReject = js.FuncOf(func(_ js.Value, args []js.Value) any {
		errCh <- args
		return nil
	})

	// Attach handlers: .then() for resolve, .catch() for reject
	promise.Call("then", onResolve).Call("catch", onReject)

	// Block until one handler fires, then release both
	select {
	case results := <-resCh:
		onResolve.Release()
		onReject.Release()
		return results, nil
	case errs := <-errCh:
		onResolve.Release()
		onReject.Release()
		return nil, errs
	}
}
