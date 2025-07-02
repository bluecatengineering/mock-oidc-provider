#!/usr/bin/env node
'use strict';

const {readFileSync} = require('node:fs');
const {createServer: createHttpServer} = require('node:http');
const {createServer: createHttpsServer} = require('node:https');
const {randomBytes, createHash} = require('node:crypto');

const express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const {generateKeyPair, exportJWK, decodeJwt, importJWK, SignJWT} = require('jose');
const {parse} = require('yaml');

const {floor} = Math;
const {json, urlencoded} = express;

const supportedCodeChallengeMethods = ['plain', 'S256'];

const defaultUsers = [
	{sub: 'foo', idClaims: {name: 'Foo', email: 'foo@example.com'}},
	{sub: 'bar', idClaims: {name: 'Bar', email: 'bar@example.com'}},
];

const createToken = () => randomBytes(16).toString('base64url');

const encodeVerifier = (verifier, challengeMethod) =>
	challengeMethod === 'plain' ? verifier : createHash('sha256').update(verifier).digest('base64url');

const getIssuer = (req) => `${req.protocol}://${req.headers.host}/`; // ending in '/' for Auth0 compatibility

const buildBaseClaims = (req, ttl, aud) => {
	const iss = getIssuer(req);
	const iat = floor(Date.now() / 1000);
	const nbf = iat - 5;
	const exp = iat + ttl;
	return {iss, aud, iat, nbf, exp};
};

const signJwt = (header, payload, key) => new SignJWT(payload).setProtectedHeader(header).sign(key);

const buildHeader = (jwk) => ({typ: 'JWT', alg: 'RS256', kid: jwk.kid});

const buildCookie = (sessionId) => `mock-auth=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=86400`;

const sendToken = (req, res, session, jwk, ttl, aud, scope, nonce) => {
	const token = createToken();
	const header = buildHeader(jwk);
	const baseClaims = buildBaseClaims(req, ttl, aud);
	const {accessClaims: userAccessClaims, idClaims: userIdClaims, ...userClaims} = session.user;
	const accessClaims = {...userClaims, ...userAccessClaims, ...baseClaims, scope};
	const idClaims = {...userClaims, ...userIdClaims, ...baseClaims, nonce};
	session.token = token;
	return importJWK(jwk)
		.then((key) => Promise.all([signJwt(header, accessClaims, key), signJwt(header, idClaims, key)]))
		.then(([access_token, id_token]) =>
			res
				.setHeader('Set-Cookie', buildCookie(session.id))
				.json({token_type: 'bearer', expires_in: ttl, refresh_token: token, access_token, id_token})
		);
};

const sanitized = {'<': '&lt;', '>': '&gt;'};
const sanitize = (string) => string.replace(/[<>]/g, (ch) => sanitized[ch]);

const renderOptions = (users) =>
	users.map(({sub, idClaims}) => `<option value="${sub}">${idClaims?.name || sub}</option>`).join('');

const showErrorPage = (res, message) =>
	res.setHeader('Cache-Control', 'no-cache').setHeader('Content-Type', 'text/html; charset=utf-8').end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock Authentication</title>
</head>
<body>
<h1>Error</h1>
<p>${message}</p>
</body>
</html>`);

const revokeSession = (req, res, sessions, uri) => {
	const sessionId = req.cookies['mock-auth'];
	if (sessionId) {
		sessions.delete(sessionId);
		res.setHeader('Set-Cookie', `mock-auth=; Path=/; Max-Age=0`);
	}
	res.redirect(uri);
};

const handleOpenidConfiguration = (req, res) => {
	const base = `${req.protocol}://${req.headers.host}`;
	res.json({
		issuer: getIssuer(req),
		jwks_uri: `${base}/.well-known/jwks.json`,
		authorization_endpoint: `${base}/authorize`,
		token_endpoint: `${base}/oauth/token`,
		revocation_endpoint: `${base}/oauth/revoke`,
		end_session_endpoint: `${base}/endsession`,
		userinfo_endpoint: `${base}/userinfo`,
		introspection_endpoint: `${base}/introspect`,
		claims_supported: ['aud', 'email', 'exp', 'iat', 'iss', 'name', 'sub'],
		code_challenge_methods_supported: supportedCodeChallengeMethods,
		grant_types_supported: ['authorization_code', 'client_credentials', 'password', 'refresh_token'],
		id_token_signing_alg_values_supported: ['RS256'],
		response_modes_supported: ['query'],
		response_types_supported: ['code'],
		scopes_supported: ['openid', 'profile', 'email'],
		subject_types_supported: ['public'],
		token_endpoint_auth_methods_supported: ['client_secret_basic'],
		token_endpoint_auth_signing_alg_values_supported: ['RS256'],
	});
};

const handleJwks =
	({jwk: {kty, alg, kid, e, n}}) =>
	(req, res) =>
		res.json({keys: [{kty, alg, kid, e, n}]});

const handleAuthorize =
	({users, codes, sessions}) =>
	(req, res) => {
		const {
			response_type: responseType,
			client_id: clientId,
			redirect_uri: redirectUri,
			code_challenge: challenge,
			code_challenge_method: challengeMethod,
			scope,
			state,
			nonce,
		} = req.query;
		const sessionId = req.cookies['mock-auth'];
		if (responseType !== 'code') {
			showErrorPage(res, `The response type '${sanitize(responseType)}' is not supported.`);
		} else if (!supportedCodeChallengeMethods.includes(challengeMethod)) {
			showErrorPage(res, `The code challenge method '${sanitize(challengeMethod)}' is not supported.`);
		} else if (sessionId && sessions.has(sessionId)) {
			const code = createToken();
			codes.set(code, {sessionId, challenge, challengeMethod, scope, nonce});
			res.redirect(`${redirectUri}?${new URLSearchParams({code, state})}`);
		} else {
			res.setHeader('Cache-Control', 'no-cache').setHeader('Content-Type', 'text/html; charset=utf-8')
				.end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock Authentication</title>
<style>
html {
font: 400 22px Roboto, 'Open Sans', Helvetica, Arial, sans-serif;;
}
body {
margin: 1rem;
}
select, button {
font: inherit;
padding: 8px 16px;
}
form {
display: flex;
flex-direction: column;
gap: 16px;
max-width: 30rem;
margin: 0 auto;
}
</style>
</head>
<body>
<main>
<form id="form" method="GET" action="/api/form">
<h1>Mock Authentication</h1>
<div>Client ID: <output>${clientId}</output></div>
<label for="sub">Subject:</label>
<select id="sub" name="sub" autofocus>${renderOptions(users)}</select>
<button type="submit">Authorize</button>
<button type="button" name="error">Deny</button>
</form>
</main>
<script>
var form = document.getElementById('form');
var params = new URLSearchParams(${JSON.stringify({redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: challengeMethod, scope, state, nonce})});
form.onsubmit = (event) => {
	event.preventDefault();
	params.set('sub', form.elements.sub.value);
	location.replace('/api/form?' + params);
};
form.error.onclick = () => {
	params.set('error', true);
	location.replace('/api/form?' + params);
};
</script>
</body>
</html>`);
		}
	};

const handleToken =
	({users, codes, sessions, ttl, jwk}) =>
	(req, res) => {
		res.setHeader('Cache-Control', 'no-store');
		switch (req.body.grant_type) {
			case 'authorization_code': {
				const {client_id: aud, code, code_verifier: verifier} = req.body;
				const data = codes.get(code);
				if (!data) {
					return res.status(401).json({error: 'invalid_request', error_description: 'Code not found'});
				}

				codes.delete(code);
				const {sessionId, challenge, challengeMethod, scope, nonce} = data;
				if (challenge !== encodeVerifier(verifier, challengeMethod)) {
					return res.status(401).json({error: 'invalid_request', error_description: 'Incorrect code verifier'});
				}

				const session = sessions.get(sessionId);
				if (!session) {
					return res.status(401).json({error: 'invalid_request', error_description: 'Session not found'});
				}

				return sendToken(req, res, session, jwk, ttl, aud, scope, nonce);
			}
			case 'client_credentials': {
				const {scope} = req.body;
				return importJWK(jwk)
					.then((key) => signJwt(buildHeader(jwk), {...buildBaseClaims(req, ttl), scope}, key))
					.then((access_token) => ({token_type: 'bearer', expires_in: ttl, access_token}))
					.then((response) => res.json(response));
			}
			case 'password': {
				const {username: sub, scope} = req.body;
				const user = users.find((user) => user.sub === sub);
				if (!user) {
					return res.status(401).json({error: 'invalid_request', error_description: 'User not found'});
				}

				const sessionId = createToken();
				const session = {id: sessionId, user};
				sessions.set(sessionId, session);
				return sendToken(req, res, session, jwk, ttl, undefined, scope);
			}
			case 'refresh_token': {
				const {client_id: aud, refresh_token: refreshToken, scope} = req.body;
				const sessionId = req.cookies['mock-auth'];
				const session = sessions.get(sessionId);
				if (!session) {
					return res.status(401).json({error: 'login_required', error_description: 'Session not found'});
				}
				if (session.token !== refreshToken) {
					session.token = null;
					return res.status(401).json({error: 'login_required', error_description: 'Token not found'});
				}

				return sendToken(req, res, session, jwk, ttl, aud, scope);
			}
		}
		return res.status(401).json({error: 'invalid_request', error_description: 'Unexpected grant type'});
	};

const handleRevoke =
	({sessions}) =>
	(req, res) => {
		const token = req.body.token;
		for (const session of sessions) {
			if (session.token === token) {
				session.token = null;
				break;
			}
		}
		res.end();
	};

const handleEndSession =
	({sessions}) =>
	(req, res) =>
		revokeSession(req, res, sessions, req.query.post_logout_redirect_uri);

const handleUserInfo =
	({users}) =>
	(req, res) => {
		const authHeader = req.headers.authorization;
		if (!authHeader || !/^Bearer /.test(authHeader)) {
			res.status(401).json({error: 'invalid_request', error_description: 'Authentication required'});
		} else {
			const token = authHeader.slice(7);
			try {
				const decoded = decodeJwt(token);
				if (!decoded || !decoded.sub) {
					res.status(400).json({error: 'invalid_request', error_description: 'JWT is not valid'});
				} else {
					const user = users.find((user) => user.sub === decoded.sub);
					if (!user) {
						res.status(404).json({error: 'invalid_request', error_description: 'User not found'});
					} else {
						// eslint-disable-next-line no-unused-vars -- simple way to remove accessClaims from the user claims
						const {idClaims, accessClaims, ...claims} = user;
						res.json({...claims, ...idClaims});
					}
				}
			} catch (error) {
				res.status(400).json({error: 'invalid_request', error_description: error.message});
			}
		}
	};

const handleIntrospect =
	({sessions}) =>
	(req, res) =>
		res.json({active: sessions.values().some((s) => s.token === req.body.token)});

const handleLogout =
	({sessions}) =>
	(req, res) =>
		revokeSession(req, res, sessions, req.query.returnTo);

const handleForm =
	({users, codes, sessions}) =>
	(req, res) => {
		const {
			sub,
			error,
			redirect_uri: redirectUri,
			code_challenge: challenge,
			code_challenge_method: challengeMethod,
			scope,
			state,
			nonce,
		} = req.query;
		if (error) {
			res.redirect(
				`${redirectUri}?${new URLSearchParams({error: 'access_denied', error_description: 'Access has been denied'})}`
			);
		} else {
			const sessionId = createToken();
			const user = users.find((user) => user.sub === sub);
			const session = {id: sessionId, user};
			sessions.set(sessionId, session);

			const code = createToken();
			codes.set(code, {sessionId, challenge, challengeMethod, scope, nonce});
			res
				.setHeader('Set-Cookie', buildCookie(sessionId))
				.redirect(`${redirectUri}?${new URLSearchParams({code, state})}`);
		}
	};

const handleClear =
	({codes, sessions}) =>
	(req, res) => {
		codes.clear();
		sessions.clear();
		res.end('OK\n');
	};

const cors = (req, res, next) => {
	const origin = req.headers.origin;
	if (origin) {
		res.setHeader('Access-Control-Allow-Origin', origin);
		const requestMethod = req.headers['access-control-request-method'];
		if (requestMethod) {
			res.setHeader('Access-Control-Allow-Method', requestMethod);
		}
		const requestHeaders = req.headers['access-control-request-headers'];
		if (requestHeaders) {
			res.setHeader('Access-Control-Allow-Headers', requestHeaders);
		}
	}
	next();
};

const configureApp = (ttl, users, jwk) => {
	const context = {
		codes: new Map(),
		sessions: new Map(),
		ttl,
		users,
		jwk,
	};
	const app = express();
	app.use(morgan('dev'));
	app.use(json({strict: true}));
	app.use(urlencoded({extended: false}));
	app.use(cookieParser());
	app.use(cors);

	app.get('/.well-known/openid-configuration', handleOpenidConfiguration);
	app.get('/.well-known/jwks.json', handleJwks(context));
	app.get('/authorize', handleAuthorize(context));
	app.post('/oauth/token', handleToken(context));
	app.post('/oauth/revoke', handleRevoke(context));
	app.get('/endsession', handleEndSession(context));
	app.get('/userinfo', handleUserInfo(context));
	app.post('/introspect', handleIntrospect(context));

	app.get('/v2/logout', handleLogout(context));
	app.get('/api/form', handleForm(context));
	app.post('/api/clear', handleClear(context));
	return app;
};

const start = (port, ttl, users, cert, key) =>
	generateKeyPair('RS256', {extractable: true})
		.then((keyPair) => exportJWK(keyPair.privateKey))
		.then(
			(jwk) =>
				new Promise((resolve, reject) => {
					jwk.alg = 'RS256';
					jwk.kid = createToken();
					console.log(`Generated RSA key with kid "${jwk.kid}"`);
					const app = configureApp(ttl, users, jwk);

					(cert ? createHttpsServer({cert, key}, app) : createHttpServer(app)).listen(port, (error) => {
						if (error) {
							reject(error);
						} else {
							console.log(`Listening on port ${port}${cert ? ' (TLS enabled)' : ''}`);
							resolve();
						}
					});
				})
		);

const main = () => {
	const argv = process.argv;
	const env = process.env;
	let i = 2;
	let port = env.PORT ? +env.PORT : 8092;
	let ttl = env.TTL ? +env.TTL : 300;
	let usersFile = env.USERS_FILE;
	let certFile = env.CERT_FILE;
	let keyFile = env.KEY_FILE;
	let error = null;
	let help = false;
	while (i < argv.length && !help) {
		switch (argv[i++]) {
			case '-p':
			case '--port':
				port = +argv[i++];
				break;
			case '-t':
			case '--ttl':
				ttl = +argv[i++];
				break;
			case '-u':
			case '--users':
				usersFile = argv[i++];
				break;
			case '-c':
			case '--cert':
				certFile = argv[i++];
				break;
			case '-k':
			case '--key':
				keyFile = argv[i++];
				break;
			case '-h':
			case '--help':
				help = true;
				break;
			default:
				error = argv[i - 1];
				help = true;
				break;
		}
	}
	if (help) {
		if (error) console.error(`Unexpected argument: ${error}`);
		console.error(
			`Usage: ${argv[1]} [-p|--port <port>] [-t|--ttl <token ttl>] [-u|--users <YAML file>] [-c|--cert <SSL certificate>] [-k|--key <SSL key>]`
		);
		process.exit(1);
	}
	if ((certFile && !keyFile) || (keyFile && !certFile)) {
		console.error('Both the SSL certificate and key must be specified at the same time.');
		process.exit(1);
	}
	let users = defaultUsers;
	if (usersFile) {
		console.log(`Loading users from "${usersFile}"`);
		users = parse(readFileSync(usersFile, 'utf8'));
	}
	let cert, key;
	if (certFile) {
		console.log(`Loading SSL certificate from "${certFile}"`);
		cert = readFileSync(certFile);
		console.log(`Loading SSL key from "${keyFile}"`);
		key = readFileSync(keyFile);
	}
	process.once('SIGINT', () => {
		console.log('Stopping server');
		process.exit(0);
	});
	start(port, ttl, users, cert, key).catch(console.error);
};

try {
	main();
} catch (error) {
	console.error(error);
}
