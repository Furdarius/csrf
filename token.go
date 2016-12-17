package csrf

import (
	"crypto/subtle"
	"encoding/base64"
	mathRand "math/rand"
	"sync"
	"time"
)

func isEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func generateToken(length int) string {
	randomBytes := generateMathRandomBytes(length)

	return base64.URLEncoding.EncodeToString(randomBytes)
}

// Idea and realization of pseudo-random bytes generation taken from
// http://stackoverflow.com/a/31832326
// It's much faster than crypto/rand.Read([]byte)
//
// Benchmark:
//
// BenchmarkGenerateCryptoRandomBytes32-2   	  500000	      2833 ns/op
// BenchmarkGenerateCryptoRandomBytes64-2   	  300000	      4518 ns/op
// BenchmarkGenerateMathRandomBytes32-2     	 5000000	       407 ns/op
// BenchmarkGenerateMathRandomBytes64-2     	 2000000	       689 ns/op

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// randSrc is not safe for concurrent use by multiple goroutines.
var (
	randSrcMutex sync.Mutex // TODO: randSrc pool
	randSrc      = mathRand.NewSource(time.Now().UnixNano())
)

// generateMathRandomBytes returns generated pseudo-random bytes
// using math pseudo-random number generator
func generateMathRandomBytes(n int) []byte {
	b := make([]byte, n)

	randSrcMutex.Lock()
	cache := randSrc.Int63()
	randSrcMutex.Unlock()
	for i, remain := n-1, letterIdxMax; i >= 0; {
		if remain == 0 {
			randSrcMutex.Lock()
			cache = randSrc.Int63()
			randSrcMutex.Unlock()
			remain = letterIdxMax
		}

		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}

		cache >>= letterIdxBits
		remain--
	}

	return b
}
