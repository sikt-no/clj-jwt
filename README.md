# clj-jwt

![clj-jwt logo](./clj-jwt.png)

A Clojure library to handle validation of JWTs and signing claims using JSON Web Keys.

```clojure
[no.nsd/clj-jwt "0.4.5"]
```

clj-jwt wraps some of [Buddy's](https://funcool.github.io/buddy-sign/latest/) functions for validating JWTs and signing claims.
It uses a JWKS endpoint to fetch the public or private key to use for validation or signing respectively.
By using this library you can abstract away key handling as the library will automatically fetch new keys as the JWK server issues new keys.

## Usage

### Validating JWTs

You can use the `unsign` function which wraps buddy-sign's own unsign function:

```clojure
(require '[no.nsd.clj-jwt :as clj-jwt])

(clj-jwt/unsign "https://sso-stage.nsd.no/.well-known/jwks.json" "<your-token-here>")
```

Or you can use the `resolve-public-key` function with the  jws backend from
buddy-auth:

```clojure
(require '[buddy.auth.backends :as backends])
(require '[no.nsd.clj-jwt :as clj-jwt])

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
(require '[no.nsd.clj-jwt :as clj-jwt])

(clj-jwt/sign "my-local-jwks.json" "my-jwk-kid" {:sub "some-user"})
```

## Development

Ensure you have [Clojure installed](https://clojure.org/guides/getting_started).
Then clone project and run Clojure Tools Deps targets.  If you have rlwrap
installed you can use the `clj` command in place of `clojure`.

Note that you always need to include the `dev` alias when developing as this alias provides all the necessary libraries.
Refer to your editors documentation about how to connect or start a repl integrated with the editor.

```bash
# Run a development clojure repl
clojure -Adev

# Run regular old Clojure tests
clojure -Adev:test

# Exercise clojure specs
clojure -Adev:propertytest
```

You can start a REPL in the project to evaluate code.
For editor integration see [clojure guides - editor integrations](https://gitlab.nsd.no/clojure/guides/blob/master/editor.md).

### Installing 'work in progress' locally

If you are contributing code to the library you may wish to test it against a
clojure project locally to ensure everything works.

You may install your version of clj-jwt into your local m2 repository:

```bash
lein install
```

If you use clojure tools deps you can simply refer to your clj-jwt project in
the other clojure project's `deps.edn` file:

```edn
{:deps
 {clj-jwt {:local/root "/path/to/clj-jwt"}}}
```

## Making new release

You need [Leiningen installed](https://leiningen.org/#install). The
`project.clj` file specifies a `snapshot` and `release` repository. You need to
configure credentials for each of the repositories in your
`~/.lein/credentials.clj` file. Example:

```edn
{"https://nexus.nsd.no/repository/maven-snapshots/" {:username "your-nexus-user"
                                                     :password "super secret password"}
 "https://nexus.nsd.no/repository/maven-releases/" {:username "your-nexus-user"
                                                     :password "super secret password"}}
```

To make a release follow these points:

### Run tests and property tests (specs)

```bash
# Run regular old Clojure tests
clojure -Atest

# Exercise clojure specs
clojure -Apropertytest
```

### Bump version number in project.clj

There are different scenarios where you need to increment the version number
differently. The gist of it is that this library follows
[semver](https://semver.org/) with SNAPSHOT releases for test releases.

Making final release from snapshot builds:

0.2.0-SNAPSHOT -> 0.2.0

Making snapshot release from release build:

0.2.0 -> 0.3.0-SNAPSHOT

Making patch release from release build:

0.2.0 -> 0.2.1

Then run the lein deploy command:

### Run leiningen deploy

To build jar and upload to [NSD's Nexus](https://nexus.nsd.no):

```bash
lein deploy
```

### Finally commit, push and tag release

Add a new changelog entry in the `CHANGELOG.md` file.
Commit the project.clj version bump, push it to the Gitlab repository, and tag
it. The tag message should describe the changes made, and the release notes can
link to the release in Nexus.

PS! It is not necessary to commit and push SNAPSHOT releases. SNAPSHOT releases
are mutable and should not be tagged in git.

## License

Copyright © 2018 NSD - NORSK SENTER FOR FORSKNINGSDATA AS

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
    
