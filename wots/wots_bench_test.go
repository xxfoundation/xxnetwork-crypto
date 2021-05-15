////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"crypto/rand"
	"testing"
)

const MsgSize = 256

type testData struct {
	msg    []byte
	seed   []byte
	pSeed  []byte
}

var t *testData
var p *Params

func initTestData() {
	t = new(testData)
	t.msg = make([]byte, MsgSize)
	_, _ = rand.Read(t.msg)
	t.seed = make([]byte, SeedSize)
	_, _ = rand.Read(t.seed)
	t.pSeed = make([]byte, SeedSize)
	_, _ = rand.Read(t.pSeed)
}

func benchmarkDecodeParams(b *testing.B) {
	key := NewKeyFromSeed(p, t.seed, t.pSeed)
	sig := key.Sign(t.msg)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		out := make([]byte, 0, PKSize)
		for pb.Next() {
			out = p.Decode(out, t.msg, sig[1:])
			out = out[:0]
		}
	})
}

func BenchmarkDecodeParallel(b *testing.B) {
	initTestData()
	for enc := ParamsEncoding(0); enc < ParamsEncodingLen; enc++ {
		p = DecodeParams(enc)
		b.Run(p.String(), benchmarkDecodeParams)
	}
}
