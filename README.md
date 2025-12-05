# Mock OpenID Connect provider

![ESLint](https://github.com/bluecatengineering/mock-oidc-provider/workflows/ESLint/badge.svg)
![CodeQL](https://github.com/bluecatengineering/mock-oidc-provider/workflows/CodeQL/badge.svg)
[![GitHub license](https://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/bluecatengineering/mock-oidc-provider/blob/main/LICENSE)
[![npm version](https://img.shields.io/npm/v/@bluecateng/mock-oidc-provider.svg?style=flat)](https://www.npmjs.com/package/@bluecateng/mock-oidc-provider)

A mock OpenID Connect provider which can be used for testing.

This provider is based on the [OpenID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html),
and inspired by [OpenID Provider Mock](https://github.com/geigerzaehler/oidc-provider-mock)
and [oauth2-mock-server](https://github.com/axa-group/oauth2-mock-server).
JWT and cryptography functions provided by [jose](https://github.com/panva/jose).

> **Important security note:**
> This mock provider is intended for development and testing only. It lacks comprehensive security features, persistent storage, and full compliance with all OpenID Connect requirements.
> **Do not use it in production or expose it to the public internet.**
>
> - No CSRF protection
> - No rate limiting or abuse protection
> - All sessions and tokens are stored in memory only
> - Session cookies require either localhost or HTTPS
> - Not all OIDC spec features and advanced claims are implemented

## Usage

You can run the provider via `npx` or `docker`.

### With `npx`

`npx @bluecateng/mock-oidc-provider`

### With `docker`

`docker run --name mock-oidc-provider --rm -p 8092:80 ghcr.io/bluecatengineering/mock-oidc-provider`

## Configuration

### Arguments

The server can be configured either via command-line parameters or environment variables.

| command line   | env var    | description                                                   | default |
| -------------- | ---------- | ------------------------------------------------------------- | ------- |
| -p, --port     | PORT       | port where the HTTP server will listen                        | 8092    |
| -s, --tls-port | TLS_PORT   | port where the HTTPS server will listen (when TLS is enabled) | 8443    |
| -t, --ttl      | TTL        | time to live for tokens (seconds)                             | 300     |
| -u, --users    | USERS_FILE | path to a users YAML file                                     |         |
| -c, --cert     | CERT_FILE  | TLS certificate file (see TLS section)                        |         |
| -k, --key      | KEY_FILE   | TLS private key file (see TLS section)                        |         |
| -j, --jwk      | JWK_FILE   | path to a JWK file used for signing tokens                    |         |
| --save-jwk     |            | save the active JWK to the given file                         |         |

If `--jwk` is not provided, a random RSA key is generated automatically.
Use `--save-jwk <file>` to write the active JWK (whether generated or loaded) to a JSON file for later reuse.

### Users

By default, two users are provided (`foo` and `bar`).
If a users file is supplied, it **replaces** the default users.

Users file format (YAML):

- The top-level value must be an array.
- Each array entry must be an object containing:
  - `sub` (string): the subject identifier.
  - Optional additional claims to be included in both the access and the ID tokens.
  - Optional `idClaims`: included **only** in ID tokens.
  - Optional `accessClaims`: included **only** in access tokens.

#### Example

```yaml
- sub: eeny
  email: eeny@example.com
  idClaims:
    name: Eeny
  accessClaims:
    mock: a
- sub: meeny
  email: meeny@example.com
  idClaims:
    name: Meeny
  accessClaims:
    mock: b
- sub: miny
  email: miny@example.com
  idClaims:
    name: Miny
  accessClaims:
    mock: c
```

### TLS

To enable HTTPS, specify both:

- `--cert <file>`
- `--key <file>`

These files are passed directly to
[`https.createServer`](https://nodejs.org/docs/latest-v22.x/api/https.html#httpscreateserveroptions-requestlistener).

When TLS is enabled:

- An HTTP server **always** runs on `--port` (default: 8092).
- An HTTPS server also runs on `--tls-port` (default: 8443).

If TLS is not enabled (no cert/key specified), only the HTTP server runs.

## Endpoints

The discovery document (`/.well-known/openid-configuration`) exposes all supported endpoints.

Main endpoints:

- `/.well-known/openid-configuration` — OIDC discovery metadata
- `/.well-known/jwks.json` — JWKS for token validation
- `/authorize` — Authorization endpoint
- `/oauth/token` — Token endpoint
- `/oauth/revoke` — Token revocation
- `/oidc/logout` — End session
- `/userinfo` — UserInfo endpoint
- `/introspect` — Token introspection
- `/api/clear` — **Testing utility**: clears all sessions and authorization codes

## Workflows Supported

- Authorization Code Flow
- Authorization Code Flow with PKCE
- Client Credentials Flow
- Resource Owner Password Flow

> The **Implicit Flow** is _not_ supported.

## Supported Claims and Scopes

- All user object properties appear in both access and ID tokens except:
  - `idClaims`: ID token only
  - `accessClaims`: access token only
- `/userinfo` returns all user claims; scope is **not enforced**.
- Standard OIDC scopes (`openid`, `profile`, `email`) are accepted but not strictly validated.

## Known Limitations

- Not production-ready.
- Not fully OIDC-compliant.
- All state is stored in memory.
- No CSRF protection, no rate limiting.
- Minimal validation of client authentication.
- Should only be used in local development or CI environments.

## Example OIDC Client Configuration

Discovery URL:

```
http://localhost:8092/.well-known/openid-configuration
```

Client configuration:

- **Client ID:** any string (client authentication is not enforced)
- **Redirect URI:** must match the value passed to `/authorize`
- **Scopes:** `openid profile email` or as needed
- **Response type:** `code`

## License

[ISC](LICENSE)
