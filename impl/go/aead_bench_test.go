// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"crypto/rand"
	"strconv"
	"testing"
)

// Benchmarks in this file measure SealAES256GCM/OpenAES256GCM -- the per-frame AEAD
// cost on the record-layer hot path -- at payload sizes representative of a small
// control frame, a typical application frame, and a large streamed chunk near
// MaxFrameSize. Measure with a NON-race build:
// `cd impl/go && GOWORK=off go test -bench=. -benchmem -run=^$`. Do not pin a headline
// ns/op captured under `go test -race` -- race instrumentation distorts AEAD timings.

// aeadBenchSizes are representative payload sizes: a bare control frame (0 B), a small
// application body (64 B), a typical body (1 KiB), and a large streamed chunk (64 KiB).
var aeadBenchSizes = []int{0, 64, 1024, 64 * 1024}

func benchAEADFixture(size int) (key [32]byte, iv [12]byte, aad, plaintext []byte) {
	if _, err := rand.Read(key[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(iv[:]); err != nil {
		panic(err)
	}
	aad = make([]byte, 21) // the 21-octet header prefix HeaderPrefix produces
	if _, err := rand.Read(aad); err != nil {
		panic(err)
	}
	plaintext = make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		panic(err)
	}
	return key, iv, aad, plaintext
}

// BenchmarkSealAES256GCM measures encrypting a plaintext frame payload of each
// representative size.
func BenchmarkSealAES256GCM(b *testing.B) {
	for _, size := range aeadBenchSizes {
		key, iv, aad, plaintext := benchAEADFixture(size)
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for n := 0; b.Loop(); n++ {
				if _, err := SealAES256GCM(key, iv, uint64(n), aad, plaintext); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpenAES256GCM measures decrypting (and authenticating) a sealed frame
// payload of each representative size. Each benchmark seals ONE fixed sealed value up
// front under a fixed sequence number and repeatedly opens that same value, so the
// loop measures Open in isolation rather than re-measuring Seal on every iteration.
func BenchmarkOpenAES256GCM(b *testing.B) {
	for _, size := range aeadBenchSizes {
		key, iv, aad, plaintext := benchAEADFixture(size)
		const seq = 42
		sealed, err := SealAES256GCM(key, iv, seq, aad, plaintext)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := OpenAES256GCM(key, iv, seq, aad, sealed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSealOpenRoundTrip measures the combined per-frame Seal+Open cost -- the
// figure closest to the actual sender+receiver work one frame costs on the wire.
func BenchmarkSealOpenRoundTrip(b *testing.B) {
	for _, size := range aeadBenchSizes {
		key, iv, aad, plaintext := benchAEADFixture(size)
		b.Run(sizeLabel(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for n := 0; b.Loop(); n++ {
				sealed, err := SealAES256GCM(key, iv, uint64(n), aad, plaintext)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := OpenAES256GCM(key, iv, uint64(n), aad, sealed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func sizeLabel(size int) string {
	switch {
	case size == 0:
		return "0B"
	case size < 1024:
		return strconv.Itoa(size) + "B"
	case size < 1024*1024:
		return strconv.Itoa(size/1024) + "KiB"
	default:
		return strconv.Itoa(size/(1024*1024)) + "MiB"
	}
}
