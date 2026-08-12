'use strict';

const {after, before, describe, test} = require('node:test');
const assert = require('node:assert/strict');

const {startServer, request, getTokens, decodeJwt} = require('./helpers');

describe('discovery', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	const discover = (headers) =>
		request(server.base, '/.well-known/openid-configuration', {headers}).then((response) => response.json());

	test('derives the issuer from the request', async () => {
		const document = await discover();
		assert.equal(document.issuer, `${server.base}/`);
	});

	test('publishes every endpoint under the issuer', async () => {
		const document = await discover();
		assert.equal(document.authorization_endpoint, `${server.base}/authorize`);
		assert.equal(document.token_endpoint, `${server.base}/oauth/token`);
		assert.equal(document.revocation_endpoint, `${server.base}/oauth/revoke`);
		assert.equal(document.end_session_endpoint, `${server.base}/oidc/logout`);
		assert.equal(document.userinfo_endpoint, `${server.base}/userinfo`);
		assert.equal(document.introspection_endpoint, `${server.base}/introspect`);
		assert.equal(document.jwks_uri, `${server.base}/.well-known/jwks.json`);
	});

	test('follows the forwarded protocol and host', async () => {
		const document = await discover({'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'auth.example.com'});
		assert.equal(document.issuer, 'https://auth.example.com/');
		assert.equal(document.authorization_endpoint, 'https://auth.example.com/authorize');
	});

	test('advertises only what is implemented', async () => {
		const document = await discover();
		assert.deepEqual(document.response_types_supported, ['code']);
		assert.deepEqual(document.code_challenge_methods_supported, ['plain', 'S256']);
		assert.deepEqual(document.grant_types_supported, [
			'authorization_code',
			'client_credentials',
			'password',
			'refresh_token',
		]);
	});

	test('serves a signing key without any private material', async () => {
		const {keys} = await request(server.base, '/.well-known/jwks.json').then((response) => response.json());
		assert.equal(keys.length, 1);
		assert.equal(keys[0].use, 'sig');
		assert.equal(keys[0].alg, 'RS256');
		for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
			assert.ok(!(field in keys[0]), `the private field ${field} must not be published`);
		}
	});
});

describe('discovery with a configured issuer', () => {
	let server;
	before(async () => (server = await startServer(['--issuer', 'https://auth.example.com/'])));
	after(() => server.stop());

	test('uses the configured value verbatim', async () => {
		const document = await request(server.base, '/.well-known/openid-configuration').then((r) => r.json());
		assert.equal(document.issuer, 'https://auth.example.com/');
	});

	test('joins the endpoints without doubling the separator', async () => {
		const document = await request(server.base, '/.well-known/openid-configuration').then((r) => r.json());
		assert.equal(document.authorization_endpoint, 'https://auth.example.com/authorize');
	});

	test('keeps the issuer even when the forwarded headers disagree', async () => {
		const document = await request(server.base, '/.well-known/openid-configuration', {
			headers: {'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'somewhere.else'},
		}).then((r) => r.json());
		assert.equal(document.issuer, 'https://auth.example.com/');
		assert.equal(document.token_endpoint, 'https://auth.example.com/oauth/token');
	});

	test('issues tokens whose iss matches the published issuer', async () => {
		const document = await request(server.base, '/.well-known/openid-configuration').then((r) => r.json());
		const tokens = await getTokens(server.base);
		assert.equal(decodeJwt(tokens.access_token).iss, document.issuer);
		assert.equal(decodeJwt(tokens.id_token).iss, document.issuer);
	});
});

describe('discovery with an issuer that has no trailing slash', () => {
	let server;
	before(async () => (server = await startServer(['--issuer', 'https://auth.example.com'])));
	after(() => server.stop());

	test('does not add one', async () => {
		const document = await request(server.base, '/.well-known/openid-configuration').then((r) => r.json());
		assert.equal(document.issuer, 'https://auth.example.com');
		assert.equal(document.authorization_endpoint, 'https://auth.example.com/authorize');
	});
});
