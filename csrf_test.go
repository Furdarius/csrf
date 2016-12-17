package csrf

import (
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestNew(t *testing.T) {
	defaultSecure := false
	testOutput := "test handler"

	h := getTestHandler(testOutput)
	ds := New(h)

	// Check if ds.next is test handler

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	ds.next.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK || rr.Body.String() != testOutput {
		t.Error("ds.next is not test handler")
	}

	// Check if ds.secure is default
	if ds.secure != defaultSecure {
		t.Errorf("ds.secure is not default: expected %t, actual %t", defaultSecure, ds.secure)
	}
}

func TestDoubleSubmit_SetSecure(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())

	h := getTestHandler("")
	ds := New(h)

	var st bool
	for i := 0; i < 20; i++ {
		st = rand.Intn(1) != 0
		ds.SetSecure(st)

		if ds.secure != st {
			t.Errorf("ds.SetSecure(%t) failed: ds.secure expected %t, actual %t", st, st, ds.secure)
		}
	}
}

func TestDoubleSubmit_SetErrHandler(t *testing.T) {
	testOutput := "error handler"

	ds := New(getTestHandler(""))
	ds.SetErrHandler(getTestErrorHandler(testOutput))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	ds.err(rr, req, errors.New(""))

	if status := rr.Code; status != errorStatusCode || rr.Body.String() != testOutput {
		t.Errorf("Wrong handler in ds.err: status expected %v, actual %v, body expected \"%v\", actual \"%v\"",
			errorStatusCode, status,
			testOutput, rr.Body.String())
	}
}

func TestDoubleSubmit_ServeHTTP(t *testing.T) {
	testHandler := "test handler output"
	errHandlerOutput := "err handler output"

	// tokenReceiveMethod := "GET"

	tests := []struct {
		method         string
		mustValidate   bool
		secure         bool // is https
		cookie, header string
		expectedStatus int
	}{
		{
			method:         "GET",
			mustValidate:   false,
			secure:         false,
			expectedStatus: http.StatusOK,
		},
		{
			method:         "GET",
			mustValidate:   false,
			secure:         true,
			expectedStatus: http.StatusOK,
		},
		{
			method:         "HEAD",
			secure:         false,
			expectedStatus: http.StatusOK,
		},
		{
			method:         "TRACE",
			secure:         false,
			expectedStatus: http.StatusOK,
		},
		{
			method:         "OPTIONS",
			secure:         false,
			expectedStatus: http.StatusOK,
		},
		{
			method:         "POST",
			secure:         false,
			expectedStatus: http.StatusOK,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
		{
			method:         "POST",
			secure:         true,
			expectedStatus: http.StatusForbidden,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
		{
			method:         "POST",
			secure:         true,
			expectedStatus: http.StatusForbidden,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "anouthertoken",
		},
		{
			method:         "PUT",
			secure:         false,
			expectedStatus: http.StatusOK,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
		{
			method:         "DELETE",
			secure:         false,
			expectedStatus: http.StatusOK,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
		{
			method:         "CONNECT",
			secure:         false,
			expectedStatus: http.StatusOK,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
		{
			method:         "PATCH",
			secure:         false,
			expectedStatus: http.StatusOK,
			cookie:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
			header:         "R0NlTVpvT3F5YmZRQ0xCUXNod3VOTHRGempiZ0JEbXc=",
		},
	}

	ds := New(getTestHandler(testHandler))
	ds.SetErrHandler(getTestErrorHandler(errHandlerOutput))

	for _, test := range tests {
		ds.SetSecure(test.secure)

		target := "/"
		if test.secure {
			target = "https://"
		}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(test.method, target, nil)

		req.Header.Set(headerName, test.header)
		req.AddCookie(&http.Cookie{
			Name:     headerName,
			Value:    test.cookie,
			MaxAge:   expiration * 60,
			HttpOnly: true,
			Secure:   test.secure,
		})

		ds.ServeHTTP(rr, req)

		//Check status code
		if rr.Code != test.expectedStatus {
			t.Errorf("ds.ServeHTTP failed on \"%s\": status expected %d, actual %d",
				test.method, test.expectedStatus, rr.Code)
		}

		if test.expectedStatus == errorStatusCode {
			continue
		}
		// Check cookies
		tmpReq := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
		_, err := tmpReq.Cookie(headerName)
		if err != nil {
			t.Errorf("cookie retrieving failed: %v", err)
		}
	}
}
