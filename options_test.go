package csrf

// Options realization from
// https://github.com/gorilla/csrf/blob/master/options.go
// Copyright (c) 2015, Matt Silverlock (matt@eatsleeprepeat.net) All rights
// reserved.

import (
	"net/http"
	"reflect"
	"testing"
)

// Tests that options functions are applied to the middleware.
func TestOptions(t *testing.T) {
	var h http.Handler

	age := 30
	ageSec := age * 60
	domain := "example.io"
	header := "X-CSRF-Token"
	errorHandler := unauthorizedHandler
	cookie := "X-CSRF-Token"

	testOpts := []Option{
		MaxAge(age),
		Domain(domain),
		Secure(false),
		RequestHeader(header),
		ErrHandler(errorHandler),
		CookieName(cookie),
	}

	// Parse our test options and check that they set the related struct fields.
	cs := parseOptions(h, testOpts...)

	if cs.opts.MaxAge != ageSec {
		t.Errorf("MaxAge not set correctly: got %v want %v", cs.opts.MaxAge, ageSec)
	}

	if cs.opts.Domain != domain {
		t.Errorf("Domain not set correctly: got %v want %v", cs.opts.Domain, domain)
	}

	if cs.opts.Secure != false {
		t.Errorf("Secure not set correctly: got %v want %v", cs.opts.Secure, false)
	}

	if cs.opts.RequestHeader != header {
		t.Errorf("RequestHeader not set correctly: got %v want %v", cs.opts.RequestHeader, header)
	}

	if !reflect.ValueOf(cs.opts.ErrHandler).IsValid() {
		t.Errorf("ErrHandler not set correctly: got %v want %v",
			reflect.ValueOf(cs.opts.ErrHandler).IsValid(), reflect.ValueOf(errorHandler).IsValid())
	}

	if cs.opts.CookieName != cookie {
		t.Errorf("CookieName not set correctly: got %v want %v",
			cs.opts.CookieName, cookie)
	}
}
