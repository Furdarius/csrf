package csrf

// Options realization from
// https://github.com/gorilla/csrf/blob/master/options.go
// Copyright (c) 2015, Matt Silverlock (matt@eatsleeprepeat.net) All rights
// reserved.

import "net/http"

// Option describes a functional option for configuring the CSRF handler.
type Option func(*DoubleSubmit)

// MaxAge sets the maximum age (in minutes) of a CSRF token's underlying cookie.
// Defaults to 1 hour.
func MaxAge(age int) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.MaxAge = age * 60
	}
}

// Domain sets the cookie domain. Defaults to the current domain of the request
// only (recommended).
//
// This should be a hostname and not a URL. If set, the domain is treated as
// being prefixed with a '.' - e.g. "example.com" becomes ".example.com" and
// matches "www.example.com" and "secure.example.com".
func Domain(domain string) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.Domain = domain
	}
}

// Secure sets the 'Secure' flag on the cookie. Defaults to true (recommended).
// Set this to 'false' in your development environment otherwise the cookie won't
// be sent over an insecure channel. Setting this via the presence of a 'DEV'
// environmental variable is a good way of making sure this won't make it to a
// production environment.
func Secure(s bool) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.Secure = s
	}
}

// ErrHandler allows you to change the handler called when CSRF request
// processing encounters an invalid token or request. A typical use would be to
// provide a handler that returns a static HTML file with a HTTP 403 status. By
// default a HTTP 403 status and a plain text CSRF failure reason are served.
func ErrHandler(h ErrorHandler) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.ErrHandler = h
	}
}

// RequestHeader allows you to change the request header the CSRF middleware
// inspects. The default is X-CSRF-Token.
func RequestHeader(header string) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.RequestHeader = header
	}
}

// CookieName changes the name of the CSRF cookie issued to clients.
//
// Note that cookie names should not contain whitespace, commas, semicolons,
// backslashes or control characters as per RFC6265.
func CookieName(name string) Option {
	return func(ds *DoubleSubmit) {
		ds.opts.CookieName = name
	}
}

// parseOptions parses the supplied options functions and returns a configured
// csrf handler.
func parseOptions(h http.Handler, opts ...Option) *DoubleSubmit {
	// Set the handler to call after processing.
	ds := &DoubleSubmit{
		h: h,
	}

	// Default to true. See Secure & HttpOnly function comments for rationale.
	// Set here to allow package users to override the default.
	ds.opts.Secure = true

	// Range over each options function and apply it
	// to our csrf type to configure it. Options functions are
	// applied in order, with any conflicting options overriding
	// earlier calls.
	for _, option := range opts {
		option(ds)
	}

	return ds
}
