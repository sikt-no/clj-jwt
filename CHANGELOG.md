# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## [Unreleased]

## [v0.4.1] - 2019-07-30
### Changed
- Use defonce to define keystore atom to prevent accidental redefinitions in upstream project's development
- Update dependencies to latest feature/patch versions

## [v0.4.0] - 2019-06-06
### Added
- New sign function to sign claims and generate JWTs based on private key in JWK
- resolve-public-key function replaces resolve-key function
- resolve-private-key function makes it possible to resolve private keys from JWKS

### Changed
- resolve-key funtion made private as it is now used by resolve-public-key and resolve-private-key

## [v0.3.2] - 2018-11-16
### Changed
- Changed log level from error to info for public key lookup error

## [v0.3.1] - 2018-11-08
### Changed
- Improved logging

## [v0.3.0] - 2018-09-20
### Changed
- Swapped argument order for unsign function to make partial application easier

## [v0.2.1] - 2018-09-20
### Added
- Error logging for failing key resolve

## [v0.2.0] - 2018-09-19
### Added
- Added specs for unsign and generator for ::jwt
- Added logging for retry in resolve-key function

## [v0.1.0] - 2018-09-18
### Added
- Initial implementation of clj-jwt library.
- Function `resolve-key` that fetches jwks keys and returns a PublicKey given the kid in the jwt header.
- Function `unsign` which tries to validate a jwt given a jwks URL and a jwt.

[Unreleased]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.4.1...HEAD
[v0.4.1]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.4.0...v0.4.1
[v0.4.0]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.3.2...v0.4.0
[v0.3.2]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.3.1...v0.3.2
[v0.3.1]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.3.0...v0.3.1
[v0.3.0]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.2.1...v0.3.0
[v0.2.1]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.2.0...v0.2.1
[v0.2.0]: https://gitlab.nsd.no/clojure/clj-jwt/compare/v0.1.0...v0.2.0
