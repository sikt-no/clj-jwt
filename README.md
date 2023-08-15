# clj-jwt

![clj-jwt logo](./clj-jwt.png)

A Clojure library to handle validation of JWTs and signing claims using JSON Web Keys.

[![Clojars Project](https://img.shields.io/clojars/v/com.github.sikt-no/clj-jwt.svg?include_prereleases)](https://clojars.org/com.github.sikt-no/clj-jwt)

```clojure
com.github.sikt-no/clj-jwt {:git/tag "0.5.89" :git/sha "a868040"}
; or:
com.github.sikt-no/clj-jwt {:mvn/version "0.5.89"}
```

clj-jwt wraps some of [Buddy's](https://funcool.github.io/buddy-sign/latest/) functions for validating JWTs and signing claims.
It uses a JWKS endpoint to fetch the public or private key to use for validation or signing respectively.
By using this library you can abstract away key handling as the library will automatically fetch new keys as the JWK server issues new keys.

## Usage

### Validating JWTs

You can use the `unsign` function which wraps buddy-sign's own unsign function:

```clojure
(require '[com.github.sikt-no.clj-jwt :as clj-jwt])

(clj-jwt/unsign "https://sso-stage.nsd.no/.well-known/jwks.json" "<your-token-here>")
```

Or you can use the `resolve-public-key` function with the  jws backend from
buddy-auth:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[com.github.sikt-no.clj-jwt :as clj-jwt])

(def auth-backend
  (backends/jws {:secret (partial clj-jwt/resolve-public-key "https://sso-stage.nsd.no/.well-known/jwks.json")
                 :token-name "Bearer"
                 :authfn (fn [claims] claims)
                 :on-error (fn [request err] nil)
                 :options {:alg :rs256}}))
```

### Signing claims (creating tokens)

You can sign your own tokens if your JSON web token contains a private key component.
The `sign` function expects a jwks URL/path, a key id, the claims to sign, and optionally options to the buddy sign function.

```clojure
(require '[com.github.sikt-no.clj-jwt :as clj-jwt])

(clj-jwt/sign "my-local-jwks.json" "my-jwk-kid" {:sub "some-user"})
```

## Development

Ensure you have [Clojure installed](https://clojure.org/guides/getting_started).
Then clone project and run Clojure Tools Deps targets.  If you have rlwrap
installed you can use the `clj` command in place of `clojure`.

Refer to your editors documentation about how to connect or start a repl integrated with the editor.

```bash
# Run a development clojure repl
clojure -Adev

# Run regular old Clojure tests
clojure -X:test

# Exercise clojure specs
clojure -X:propertytest
```

### Installing 'work in progress' locally

You can simply refer to your clj-jwt project in
the other clojure project's `deps.edn` file:

```edn
{:deps
 {clj-jwt {:local/root "/path/to/clj-jwt"}}}
```

## Making a new release

Go to [https://github.com/sikt-no/clj-jwt/actions/workflows/release.yml](https://github.com/sikt-no/clj-jwt/actions/workflows/release.yml)
and press `Run workflow`.

## Further reading

[RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)

[RFC 8725 - JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)

[RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)

## License

Copyright © 2022 Sikt - Norwegian Agency for Shared Services in Education and Research

Copyright © 2018—2021 NSD - NORSK SENTER FOR FORSKNINGSDATA AS

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
