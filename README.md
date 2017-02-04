# Furdarius\CSRF
[![Build Status](https://travis-ci.org/Furdarius/csrf.svg?branch=master)](https://travis-ci.org/Furdarius/csrf) [![Coverage Status](https://coveralls.io/repos/github/Furdarius/csrf/badge.svg?branch=master)](https://coveralls.io/github/Furdarius/csrf?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/furdarius/csrf)](https://goreportcard.com/report/github.com/furdarius/csrf)

Library provides powerful **stateless** and fast (`~638 ns/op` *token generation*) **CSRF protection** using idea of [Double Submit](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie)

Token value is stored in cookie and returned to the client with header (Ex: `X-CSRF-Token`).

To ensure high level of protection, tokens are changed on **every request**. Thus, multi-tab doesn't supporting from the box. For a good user experience developer must provide multi-tab token synchronization. It can be done using browser [localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Storage/LocalStorage) and [StorageEvent](https://developer.mozilla.org/en-US/docs/Web/API/StorageEvent)

## Installation

With a properly configured Go toolchain:
```sh
go get github.com/furdarius/csrf
```

## Usage

Furdarius/csrf is easy to use: add the middleware to your router with the below:
    
```go
// .. router init ..

handler := csrf.Middleware(csrf.Secure(cfg.IsHttps))(router)

http.ListenAndServe(":8000", handler)
```

Now you have ready-to-use CSRF-protection on **non-safe** http-methods: `POST`, `PUT`, `PATCH`, `DELETE`.

On the client side token value must be taken from the `X-CSRF-Token` header. On [request](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader) send it back on server as same header.

```javascript
myReq.setRequestHeader("X-CSRF-Token", tokenValueHere);
```


## Options

You can customize setting of middleware using options.


```go
handler := csrf.Middleware(csrf.Secure(true), csrf.MaxAge(30), csrf.CookieName("MYNAME"))
```

### Available options:


#### MaxAge
MaxAge sets the maximum age (in minutes) of a CSRF token's underlying cookie.

```go
func MaxAge(age int) Option
```

Default: 1 hour.

#### Domain
Domain sets the cookie domain.

This should be a hostname and not a URL. If set, the domain is treated as
being prefixed with a `.` - e.g. `domain.io` becomes `.domain.io` and
matches `www.domain.io` and `secure.domain.io`.

```go
func Domain(age int) Option
```

Default: current domain of the request only (*recommended*).

#### Secure

Secure sets the `Secure` flag on the cookie.

Set this to `false` in your development environment otherwise the cookie won't
be sent over an insecure channel. Setting this via the presence of a `DEV`
environmental variable is a good way of making sure this won't make it to a production environment.


```go
func Secure(s bool) Option
```

 Default: `true` (*recommended*).

#### ErrHandler

ErrHandler allows you to change the handler called when CSRF request processing encounters an invalid token or request.

A typical use would be to provide a handler that returns a static HTML file with a HTTP 403 status.

```go
// ErrorHandler is function using to process error in csrf protection
type ErrorHandler func(http.ResponseWriter, *http.Request, error)

func ErrHandler(h ErrorHandler) Option
```

By default a HTTP 403 status and a plain text CSRF failure reason are served.

#### RequestHeader

RequestHeader allows you to change the request header the CSRF middleware inspects.

```go
func RequestHeader(header string) Option 
```

Default: `X-CSRF-Token`


#### CookieName

CookieName changes the name of the CSRF cookie issued to clients.

 Note that cookie names should not contain whitespace, commas, semicolons, backslashes or control characters as per [RFC6265](https://tools.ietf.org/html/rfc6265).

```go
func CookieName(name string) Option
```

Default: `X-CSRF-Token`
