# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

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
