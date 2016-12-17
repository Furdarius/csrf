package csrf

import (
	"testing"
)

var randomBytes []byte
var randomToken string

func TestGenerateToken(t *testing.T) {
	lengths := [...]int{4, 8, 16, 32, 64, 128}

	for _, length := range lengths {
		tokens := []string{}

		for n := 0; n < 20; n++ {
			token := generateToken(length)

			if len(token) == 0 {
				t.Error("generateToken failed: empty token gotten")
			}

			tokens = append(tokens, token)
		}

		// Check dublicates
		found := map[string]bool{}

		for _, token := range tokens {
			if found[token] == true {
				t.Error("generateToken failed: tokens are not unique")
			}
		}
	}
}

func TestGenerateMathRandomBytes(t *testing.T) {
	lengths := [...]int{4, 8, 16, 32, 64, 128}

	for _, length := range lengths {
		randomBytes = generateMathRandomBytes(length)

		if len(randomBytes) != length {
			t.Fatalf("generateMathRandomBytes failed: bytes count %v, expected %v",
				len(randomBytes), length)
		}
	}
}

func TestIsEqual(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"wegf", "i834fg", false},
		{"934j8gfrejnwef", "gerg", false},
		{"kk49fjg34g34g3efefg33.=12-312r4", "kk49fjg34g34g3efefg33.=12-312r4", true},
		{"jngruiwoeg383rjn", "ljknnvu3f7bef3fe==we.r.gf3f", false},
		{"912494838jjjjjjjjj", "912494838jjjjjjjjj", true},
		{"__----___---__---===--__----=---", "__----___---__---===--__----=---", true},
		{"mf=._=23r23-,,2-3r2=23", "23r=weef...2333f", false},
		{"923r84hfjwefn932r34g34", "g3499120-1enfneff", false},
	}

	for _, test := range tests {
		actual := isEqual(test.a, test.b)

		if actual != test.expected {
			t.Errorf("isEqual(%s, %s) failed: expected %t, actual %t", test.a, test.b, test.expected, actual)
		}
	}
}

// Benchmark pseudo-random bytes generation
// using math secure pseudo-random number generator
func benchmarkGenerateMathRandomBytes(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		randomBytes = generateMathRandomBytes(i)
	}
}

// TODO: Table-driven benchmarks
// https://blog.golang.org/subtests
func BenchmarkGenerateMathRandomBytes32(b *testing.B) { benchmarkGenerateMathRandomBytes(32, b) }
func BenchmarkGenerateMathRandomBytes64(b *testing.B) { benchmarkGenerateMathRandomBytes(64, b) }

func benchmarkGenerateToken(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		randomToken = generateToken(i)
	}
}

func BenchmarkGenerateToken32(b *testing.B) { benchmarkGenerateToken(32, b) }
func BenchmarkGenerateToken64(b *testing.B) { benchmarkGenerateToken(64, b) }
