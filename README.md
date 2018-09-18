# clj-jwt

![clj-jwt logo](./clj-jwt.png)

A Clojure library to handle validation of JWTs.

```clojure
[no.nsd/clj-jwt "0.1.0"]
```

The library exposes functions to handle validation of JSON web tokens. It wraps
some of [Buddy's](https://funcool.github.io/buddy-sign/latest/) jwt signature
handling functions and uses a JWKS endpoint to fetch the public keys to use for
signature validation.

## Usage

You can use the `unsign` function which wraps buddy-sign's own unsign function:

```clojure
(require '[no.nsd.clj-jwt :as clj-jwt])

(clj-jwt/unsign "https://sso-stage.nsd.no/.well-known/jwks.json" "<your-token-here>")
```

Or you can use the `resolve-key` function with the  jws backend from
buddy-auth:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[no.nsd.clj-jwt :as clj-jwt])

(def auth-backend
  (backends/jws {:secret (partial clj-jwt/resolve-key "https://sso-stage.nsd.no/.well-known/jwks.json")
                 :token-name "Bearer"
                 :authfn (fn [claims] claims)
                 :on-error (fn [request err] nil)
                 :options {:alg :rs256}}))
```

## License

Copyright © 2018 NSD - NORSK SENTER FOR FORSKNINGSDATA AS

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
