# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## [Unreleased]

## [0.5.102] - 2025-03-17
- Fix specs for multi-arity functions and `jwks-edn->keys`

## [0.5.98] - 2024-02-09
### Changed
- Bump dependencies.

## [0.5.92] - 2023-08-15
### Added
- Support automatic refresh of JWKS endpoint when using `unsign`. Maximum refresh rate is once per minute per URL. This feature supports improper rollover of keys, i.e. where the new key has the same `:kid` as previous key ([#1](https://github.com/sikt-no/clj-jwt/issues/1)).

## [0.5.81] - 2023-08-05
### Changed
- Added namespace `com.github.sikt-no.clj-jwt`. The old namespace `no.nsd.clj-jwt` will be kept identical
to the new main namespace.
- Bump dependencies, removing some CVEs.
- Use `major.minor.commit-count` version scheme.
- Simplified running tests.
### Added
- NVD check script.
- Use [build.edn](https://github.com/liquidz/build.edn) for releasing.

## [0.4.7] - 2022-11-23
### Changed
- Moved to github.com/sikt-no/clj-jwt

## [v0.4.6] - 2020-01-16
### Changed
- Library should stay silent (DEBUG level) by default
- Log error level on failure

## [v0.4.5] - 2020-01-09
### Changed
- Bugfix signing function: Include kid in header by default.
- Support char arrays as jwks-url. This can be used to test without having to use files/URLs.

## [v0.4.4] - 2020-01-07
### Changed
- Be slightly more paranoid in scopes function.

## [v0.4.3] - 2020-01-07
### Added
- Add scopes function to extract jwt scopes from claims

## [v0.4.2] - 2020-01-07
### Changed
- Support multiple jwks endpoints is supported #3
- Give meaningful error message when jwks-url or token is nil #4
- Handle token starting with `Bearer ` gracefully #5

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

[Unreleased]: https://github.com/sikt-no/clj-jwt/compare/0.5.92...HEAD
[0.5.92]: https://github.com/sikt-no/clj-jwt/compare/0.5.81...0.5.92
[0.5.81]: https://github.com/sikt-no/clj-jwt/compare/0.4.7...0.5.81
[0.4.7]: https://github.com/sikt-no/clj-jwt/compare/v0.4.6...0.4.7
[v0.4.6]: https://github.com/sikt-no/clj-jwt/compare/v0.4.5...v0.4.6
[v0.4.5]: https://github.com/sikt-no/clj-jwt/compare/v0.4.4...v0.4.5
[v0.4.4]: https://github.com/sikt-no/clj-jwt/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/sikt-no/clj-jwt/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/sikt-no/clj-jwt/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/sikt-no/clj-jwt/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/sikt-no/clj-jwt/compare/v0.3.2...v0.4.0
[v0.3.2]: https://github.com/sikt-no/clj-jwt/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/sikt-no/clj-jwt/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/sikt-no/clj-jwt/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/sikt-no/clj-jwt/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/sikt-no/clj-jwt/compare/v0.1.0...v0.2.0
