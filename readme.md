# Furdarius\CSRF
[![Build Status](https://travis-ci.org/Furdarius/csrf.svg?branch=master)](https://travis-ci.org/Furdarius/csrf)

Library provides powerful **stateless** and fast (`~638 ns/op` *token generation*) **CSRF protection** using idea of [Double Submit](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie)

Token value is stored in cookie and returned to the client with `X-CSRF-Token` header.

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
handler := csrf.New(router)
http.ListenAndServe(":8000", handler)
```

Now you have ready-to-use CSRF-protection on **non-safe** http-methods: `POST`, `PUT`, `PATCH`, `DELETE`, `CONNECT`.

On the client side token value must be taken from the `X-CSRF-Token` header. On [request](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader) send it back on server as same header.

```javascript
myReq.setRequestHeader("X-CSRF-Token", tokenValueHere);
```