package csrf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	errorStatusCode = http.StatusForbidden
)

func TestIsSafe(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", true},
		{"HEAD", true},
		{"TRACE", true},
		{"OPTIONS", true},
		{"POST", false},
		{"PUT", false},
		{"DELETE", false},
		{"CONNECT", false},
		{"PATCH", false},
		{"mik23", false},
		{"", false},
		{"   ", false},
		{"___", false},
		{"POWER", false},
	}

	for _, test := range tests {
		actual := isSafe(test.method)

		if actual != test.expected {
			t.Errorf("isSafe(%s) failed: expected %t, actual %t", test.method, test.expected, actual)
		}
	}
}

// getTestHandler returns a http.HandlerFunc for testing http middleware
func getTestHandler(output string) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, output)
	}

	return http.HandlerFunc(fn)
}

// getTestErrorHandler returns a ErrorHandler for testing http middleware
func getTestErrorHandler(output string) ErrorHandler {
	fn := func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(errorStatusCode)
		io.WriteString(w, output)
	}

	return fn
}

// TestMiddleware is a high-level test to make sure the middleware returns the
// wrapped handler with a 200 OK status.
func TestMiddleware(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", getTestHandler(""))

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p := Middleware()(s)
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie,
		"Secure") {
		t.Fatalf("cookie does not default to Secure & HttpOnly: got %v", cookie)
	}
}

// TestCookieOptions is a test to make sure the middleware correctly sets cookie options
func TestCookieOptions(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", getTestHandler(""))

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	maxAgeMin := 35
	maxAgeSec := maxAgeMin * 60

	rr := httptest.NewRecorder()
	p := Middleware(CookieName("nameoverride"), Secure(false), Domain("domainoverride"), MaxAge(maxAgeMin))(s)
	p.ServeHTTP(rr, r)

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie does not respect HttpOnly option: got %v want HttpOnly", cookie)
	}
	if strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie does not respect Secure option: got %v do not want Secure", cookie)
	}
	if !strings.Contains(cookie, "nameoverride=") {
		t.Fatalf("cookie does not respect CookieName option: got %v want %v", cookie, "nameoverride=")
	}
	if !strings.Contains(cookie, "Domain=domainoverride") {
		t.Fatalf("cookie does not respect Domain option: got %v want %v", cookie, "Domain=domainoverride")
	}
	if !strings.Contains(cookie, "Max-Age=") {
		t.Fatalf("cookie does not respect MaxAge option: got %v want Max-Age=%d", cookie, maxAgeSec)
	}
}

// Test that idempotent methods return a 200 OK status and that non-idempotent
// methods return a 403 Forbidden status when a CSRF cookie is not present.
func TestMethods(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", getTestHandler(""))
	mw := Middleware()(s)

	// Test idempontent ("safe") methods
	safeMethods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	for _, method := range safeMethods {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

	// Test non-idempotent methods (should return a 403 without a cookie set)
	nonIdempotent := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range nonIdempotent {
		r, err := http.NewRequest(method, "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, r)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}
	}
}

// Tests for failure if the cookie containing the session does not exist on a
// POST request.
func TestNoCookie(t *testing.T) {
	s := http.NewServeMux()
	mw := Middleware()(s)

	s.Handle("/", getTestHandler(""))

	// POST the token back in the header.
	r, err := http.NewRequest("POST", "http://domain.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a non-existent cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadCookie tests for failure when a cookie header is modified (malformed).
func TestBadCookie(t *testing.T) {
	s := http.NewServeMux()
	mw := Middleware()(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = generateToken(tokenLen)
	}))

	// Obtain a CSRF cookie via a GET request.
	r, err := http.NewRequest("GET", "http://domain.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, r)

	// POST the token back in the header.
	r, err = http.NewRequest("POST", "http://domain.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the cookie prefix
	badHeader := strings.Replace(headerName+"=", rr.Header().Get("Set-Cookie"), "_badCookie", -1)
	r.Header.Set("Cookie", badHeader)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://domain.io/")

	rr = httptest.NewRecorder()
	mw.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a bad cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// Responses should set a "Vary: Cookie" header to protect client/proxy caching.
func TestVaryHeader(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", getTestHandler(""))
	mw := Middleware()(s)

	r, err := http.NewRequest("HEAD", "https://domain.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Vary") != "Cookie" {
		t.Fatalf("vary header not set: got %q want %q", rr.Header().Get("Vary"), "Cookie")
	}
}
