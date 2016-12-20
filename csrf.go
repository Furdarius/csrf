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
	// Default HTTP request header to inspect
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

// options contains the optional settings for the CSRF middleware.
type options struct {
	TokenLen      int
	MaxAge        int
	Domain        string
	Secure        bool // Secure=true means that CSRF-Cookie will be Secure (HTTPS only)
	RequestHeader string
	CookieName    string
	ErrHandler    ErrorHandler
}

// DoubleSubmit is implementation of stateless CSRF protection using double submit cookie
// Persist two linked tokens on the client side,
// one via an http header, another via a cookie.
// On incoming requests, match the tokens, and generate new pair
type DoubleSubmit struct {
	h    http.Handler
	opts options
}

// Middleware return http.Handler that provides Cross-Site Request Forgery
// protection.
func Middleware(opts ...Option) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		ds := parseOptions(h, opts...)

		// Set the defaults if no options have been specified
		if ds.opts.ErrHandler == nil {
			ds.opts.ErrHandler = unauthorizedHandler
		}

		if ds.opts.MaxAge <= 0 {
			// Default of 1 hour
			ds.opts.MaxAge = expiration * 60
		}

		if ds.opts.CookieName == "" {
			ds.opts.CookieName = headerName
		}

		if ds.opts.RequestHeader == "" {
			ds.opts.RequestHeader = headerName
		}

		return ds
	}
}

func (ds *DoubleSubmit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The token will be updated for each request
	newToken := generateToken(tokenLen)

	// Check tokens only for non-safe requests (POST, PUT, DELETE, PATCH)
	if !isSafe(r.Method) {
		headerToken := r.Header.Get(ds.opts.RequestHeader)
		cookie, err := r.Cookie(ds.opts.CookieName)

		if headerToken == "" || err != nil {
			ds.opts.ErrHandler(w, r, ErrInvalidToken)

			return
		}

		cookieToken := cookie.Value

		if !isEqual(headerToken, cookieToken) {
			ds.opts.ErrHandler(w, r, ErrInvalidToken)

			return
		}
	}

	// Refresh CSRF-Token in cookie, and send newToken in header
	w.Header().Set(ds.opts.RequestHeader, newToken)
	http.SetCookie(w, &http.Cookie{
		Name:     ds.opts.CookieName,
		Value:    newToken,
		MaxAge:   ds.opts.MaxAge,
		HttpOnly: true,
		Secure:   ds.opts.Secure,
		Domain:   ds.opts.Domain,
	})

	// Set the Vary: Cookie header to protect clients from caching the response.
	w.Header().Add("Vary", "Cookie")

	ds.h.ServeHTTP(w, r)
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
