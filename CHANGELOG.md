# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [0.4.0](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.4...v0.4.0) (2026-08-12)

### Features

- allow overriding issuer URL with a static value ([dbc7e51](https://github.com/bluecatengineering/mock-oidc-provider/commit/dbc7e51defad32af5cbc426a0e3363ec0639f5b2))
- publish the endpoint URLs under the issuer ([857d738](https://github.com/bluecatengineering/mock-oidc-provider/commit/857d73864da90dfe3be7ccd26335ab28b0878cb4))
- refresh without a cookie and log out without a redirect ([08e5c32](https://github.com/bluecatengineering/mock-oidc-provider/commit/08e5c3215b8fc050d1ecc91b6d071c3494fef02a))

### Bug Fixes

- accept client_secret_basic on the token endpoint ([fcbaadb](https://github.com/bluecatengineering/mock-oidc-provider/commit/fcbaadb444db42880cbb6fd914f6dcec67eea77a)), closes [#31](https://github.com/bluecatengineering/mock-oidc-provider/issues/31)
- add use to the jwks response ([1e7da1f](https://github.com/bluecatengineering/mock-oidc-provider/commit/1e7da1f6322b05f32644da14595182c1dbd97bf9))
- answer malformed requests with an error instead of a server error ([2f1d00f](https://github.com/bluecatengineering/mock-oidc-provider/commit/2f1d00f90a5138feef663360960b63ae1e9ccd8f))
- build and publish both amd64 and arm64 images ([78c6386](https://github.com/bluecatengineering/mock-oidc-provider/commit/78c6386b5f1ffbf8d483230618315ead2c0050de))
- escape the values interpolated into the login page ([c0630c4](https://github.com/bluecatengineering/mock-oidc-provider/commit/c0630c4ccbbec805a36037915694cc3d6cf545d3))
- report startup failures and stop on SIGTERM ([2ec52a4](https://github.com/bluecatengineering/mock-oidc-provider/commit/2ec52a41a29e061ae1264a2a99d94a844304af88))
- send the claims and parameters the specs require ([f3dc482](https://github.com/bluecatengineering/mock-oidc-provider/commit/f3dc482e7cef2ff442cf32f06a1ac5d7c447ce51))

## [0.3.4](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.3...v0.3.4) (2026-04-01)

### Bug Fixes

- ensure the client audience is included in the token ([222f5d5](https://github.com/bluecatengineering/mock-oidc-provider/commit/222f5d5fbd9f357f60abd73b167ae383d59c5788))

## [0.3.3](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.2...v0.3.3) (2026-03-30)

## [0.3.2](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.1...v0.3.2) (2026-03-30)

## [0.3.1](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.3.0...v0.3.1) (2026-03-30)

### Features

- allow defining client claims for the client credentials flow ([083e049](https://github.com/bluecatengineering/mock-oidc-provider/commit/083e049032753104f6cfa81f4f4f6b5e8897c899))

## [0.3.0](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.2.0...v0.3.0) (2025-12-05)

### ⚠ BREAKING CHANGES

- the existing -p/--port option now applies only to the HTTP server
  existing users requiring a custom HTTPS port must now use -s/--tls-port

### Features

- allow both http and https servers to run simultaneously ([e39ab7a](https://github.com/bluecatengineering/mock-oidc-provider/commit/e39ab7a8be1051712ea1d0246e27b854ad7f7579))

## [0.2.0](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.1.1...v0.2.0) (2025-12-05)

### ⚠ BREAKING CHANGES

- hardcoded usages of the previous endpoint (`/endsession`)
  must be updated to `/oidc/logout`

### Features

- add options to save and load JWK files ([2313fed](https://github.com/bluecatengineering/mock-oidc-provider/commit/2313fed4b7d712d04b9073523b9345f282719db7))
- change the end session endpoint ([1649370](https://github.com/bluecatengineering/mock-oidc-provider/commit/16493703e127c6e2983697412f2119b48048307a))

## [0.1.1](https://github.com/bluecatengineering/mock-oidc-provider/compare/v0.1.0...v0.1.1) (2025-07-07)

### Bug Fixes

- fix issues found in code review ([702dd2a](https://github.com/bluecatengineering/mock-oidc-provider/commit/702dd2afd1daf3d3ae711ff44a99e2580570ecf7))
