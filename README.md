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

There are two ways to run the provider: using `npx` or `docker`.

### With `npx`

`npx @bluecateng/mock-oidc-provider`

### With `docker`

`docker run --name mock-oidc-provider --rm -p 8092:80 ghcr.io/bluecatengineering/mock-oidc-provider`

## Configuration

### Arguments

The server can be configured either using command line parameters or environment variables.
The following options are accepted:

| command line | environment var | description                                            | default |
| ------------ | --------------- | ------------------------------------------------------ | ------- |
| -p, --port   | PORT            | the port where the server will listen                  | 8092    |
| -t, --ttl    | TTL             | the time to live for the generated tokens (in seconds) | 300     |
| -u, --users  | USERS_FILE      | the path to the users file (see users section)         |         |
| -c, --cert   | CERT_FILE       | the path to the TLS certificate file (see TLS section) |         |
| -k, --key    | KEY_FILE        | the path to the TLS key file (see TLS section)         |         |

### Users

By default, the server has two users (foo and bar). Specifying a users file overrides the default users.
The users file is a YAML file with the following format:

- The top level must be an array.
- Each item in the array must be an object.
- Each object must have a `sub` property whose value is a `string`.
- Additional properties can be added to the object, which will be included as claims in both the access and the ID tokens.
- The property `idClaims` can be used to specify claims to be included in the ID token only.
- The property `accessClaims` can be used to specify claims to be included in the access token only.

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

The server can run with TLS (HTTPS) enabled by specifying both the certificate and the key files.
The files are loaded and passed to [https.createServer](https://nodejs.org/docs/latest-v22.x/api/https.html#httpscreateserveroptions-requestlistener).

When TLS is enabled, the server runs only in this mode (and not in plain HTTP).

## Endpoints

The standard [OpenID Provider Configuration Information endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) (`/.well-known/openid-configuration`)
can be used to obtain all the supported endpoints.

For convenience, here are the main endpoints:

- `/.well-known/openid-configuration` — OIDC discovery
- `/.well-known/jwks.json` — JWKS for token validation
- `/authorize` — Authorization endpoint
- `/oauth/token` — Token endpoint
- `/oauth/revoke` — Revocation endpoint
- `/endsession` — End session (logout)
- `/userinfo` — UserInfo endpoint
- `/introspect` — Token introspection
- `/api/clear` — (testing utility) clears all sessions and codes

## Workflows

The following workflows are supported:

- Authorization Code Flow
- Authorization Code Flow with Proof Key for Code Exchange (PKCE)
- Client Credentials Flow
- Resource Owner Password Flow

> The Implicit Flow is **not** supported.

## Supported Claims and Scopes

- All properties on the user object are included as claims in both access and ID tokens, except:
  - Properties under `idClaims` are included only in the ID token.
  - Properties under `accessClaims` are included only in the access token.
- The server does **not** enforce scopes when returning claims in `/userinfo`. All claims for the user are returned.
- Standard OpenID scopes (`openid`, `profile`, `email`) are accepted but not strictly validated.

## Known Limitations

- **Not production-ready:** Intended for local development and CI testing only.
- **OIDC compliance:** Not all optional OIDC parameters, claims, or error responses are implemented.
- **Session and token storage:** All state is kept in memory and will be lost on restart.
- **No rate limiting or CSRF protection:** Do not expose outside trusted development environments.

## Example OIDC Client Configuration

You can point your OIDC client to the discovery endpoint:

```
http://localhost:8092/.well-known/openid-configuration
```

Configure your client with:

- Client ID: (any string, as client secrets are not strictly checked)
- Redirect URI: Must match what you provide to `/authorize`
- Scopes: `openid profile email` (or as needed)
- Response type: `code`

## License

[ISC](LICENSE)
