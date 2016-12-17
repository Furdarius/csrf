// Package csrf provides Double Submit CSRF protection
package csrf

import (
	"errors"
	"fmt"
	"net/http"
)

const (
	// Default token length in bytes
	tokenLen = 32
	// The default HTTP request header to inspect
	headerName = "X-CSRF-Token"
	// Default expiration in minutes
	expiration = 60
)

// ErrorHandler is function using to process error in csrf protection
type ErrorHandler func(http.ResponseWriter, *http.Request, error)

var (
	// ErrInvalidToken is returned when the provided token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// DoubleSubmit is implementation of stateless CSRF protection using double submit cookie
// Persist two linked tokens on the client side,
// one via an http header, another via a cookie.
// On incoming requests, match the tokens, and generate new pair
type DoubleSubmit struct {
	next http.Handler
	err  ErrorHandler
	// secure=true means that CSRF-Cookie will be Secure (HTTPS only)
	secure bool
}

// New returns a new instance of DoubleSubmit.
func New(h http.Handler) *DoubleSubmit {
	return &DoubleSubmit{
		next:   h,
		err:    ErrorHandler(unauthorizedHandler),
		secure: false,
	}
}

// SetSecure is setter for secure attr
func (ds *DoubleSubmit) SetSecure(st bool) {
	ds.secure = st
}

// SetErrHandler is setter for err attr
func (ds *DoubleSubmit) SetErrHandler(h ErrorHandler) {
	ds.err = h
}

func (ds *DoubleSubmit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The token will be updated for each request
	newToken := generateToken(tokenLen)

	// Check tokens only for non-safe requests (POST, PUT, DELETE, PATCH)
	if !isSafe(r.Method) {
		headerToken := r.Header.Get(headerName)
		cookie, err := r.Cookie(headerName)

		if headerToken == "" || err != nil {
			ds.err(w, r, ErrInvalidToken)

			return
		}

		cookieToken := cookie.Value

		if !isEqual(headerToken, cookieToken) {
			ds.err(w, r, ErrInvalidToken)

			return
		}
	}

	// Refresh CSRF-Token in cookie, and send newToken in header
	w.Header().Set(headerName, newToken)
	http.SetCookie(w, &http.Cookie{
		Name:     headerName,
		Value:    newToken,
		MaxAge:   expiration * 60,
		HttpOnly: true,
		Secure:   ds.secure,
	})

	// Set the Vary: Cookie header to protect clients from caching the response.
	w.Header().Add("Vary", "Cookie")

	ds.next.ServeHTTP(w, r)
}

// isSafe check if method is safe (Don't change state of app)
func isSafe(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE"
}

// unauthorizedhandler sets a HTTP 403 Forbidden status and writes the
// CSRF failure reason to the response.
func unauthorizedHandler(w http.ResponseWriter, r *http.Request, reason error) {
	http.Error(w, fmt.Sprintf("%s - %s",
		http.StatusText(http.StatusForbidden), reason),
		http.StatusForbidden)
}
