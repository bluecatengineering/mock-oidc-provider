'use strict';

const {after, before, describe, test} = require('node:test');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');

const {startServer, CookieJar, request, decodeJwt, approve, getTokens} = require('./helpers');

const challengeFor = (verifier) => createHash('sha256').update(verifier).digest('base64url');
const token = (base, form, jar) => request(base, '/oauth/token', {form, jar});
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe('the authorization code grant', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('returns an access token and an ID token', async () => {
		const tokens = await getTokens(server.base, {nonce: 'n-1'});
		assert.equal(tokens.token_type, 'bearer');
		assert.equal(tokens.expires_in, 300);
		assert.ok(tokens.refresh_token);

		const id = decodeJwt(tokens.id_token);
		assert.equal(id.sub, 'foo');
		assert.equal(id.aud, 'baz');
		assert.equal(id.nonce, 'n-1');
		assert.ok(id.auth_time, 'an ID token from a user login must carry auth_time');
		assert.equal(decodeJwt(tokens.access_token).sub, 'foo');
	});

	test('accepts a code only once', async () => {
		const {code} = await approve(server.base);
		assert.equal((await token(server.base, {grant_type: 'authorization_code', client_id: 'baz', code})).status, 200);
		const replay = await token(server.base, {grant_type: 'authorization_code', client_id: 'baz', code});
		assert.equal(replay.status, 401);
	});

	test('rejects an unknown code', async () => {
		const response = await token(server.base, {grant_type: 'authorization_code', client_id: 'baz', code: 'nope'});
		assert.equal(response.status, 401);
	});

	test('rejects an unknown grant type', async () => {
		assert.equal((await token(server.base, {grant_type: 'implicit'})).status, 401);
	});
});

describe('proof key for code exchange', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	const exchange = async (challengeQuery, form) => {
		const {code} = await approve(server.base, challengeQuery);
		return token(server.base, {grant_type: 'authorization_code', client_id: 'baz', code, ...form});
	};

	test('accepts a matching S256 verifier', async () => {
		const verifier = 'a-sufficiently-long-code-verifier-value';
		const response = await exchange(
			{code_challenge: challengeFor(verifier), code_challenge_method: 'S256'},
			{code_verifier: verifier}
		);
		assert.equal(response.status, 200);
	});

	test('accepts a matching plain verifier', async () => {
		const response = await exchange(
			{code_challenge: 'plain-value', code_challenge_method: 'plain'},
			{code_verifier: 'plain-value'}
		);
		assert.equal(response.status, 200);
	});

	test('rejects a verifier that does not match', async () => {
		const response = await exchange(
			{code_challenge: challengeFor('right'), code_challenge_method: 'S256'},
			{code_verifier: 'wrong'}
		);
		assert.equal(response.status, 401);
	});

	// omitting the verifier used to reach the hash function with undefined and fail the request
	test('rejects a missing verifier without failing', async () => {
		const response = await exchange({code_challenge: challengeFor('right'), code_challenge_method: 'S256'}, {});
		assert.equal(response.status, 401);
	});

	test('rejects a repeated verifier', async () => {
		const verifier = 'a-sufficiently-long-code-verifier-value';
		const {code} = await approve(server.base, {
			code_challenge: challengeFor(verifier),
			code_challenge_method: 'S256',
		});
		const body = new URLSearchParams([
			['grant_type', 'authorization_code'],
			['client_id', 'baz'],
			['code', code],
			['code_verifier', verifier],
			['code_verifier', verifier],
		]);
		const response = await fetch(`${server.base}/oauth/token`, {method: 'POST', body, redirect: 'manual'});
		assert.equal(response.status, 401);
	});

	test('still allows an exchange without any challenge', async () => {
		assert.equal((await exchange({}, {})).status, 200);
	});
});

describe('the password grant', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('puts the client id in the ID token audience', async () => {
		const response = await token(server.base, {grant_type: 'password', username: 'foo', client_id: 'baz'});
		const tokens = await response.json();
		assert.equal(decodeJwt(tokens.id_token).aud, 'baz');
	});

	test('rejects an unknown user', async () => {
		const response = await token(server.base, {grant_type: 'password', username: 'nobody', client_id: 'baz'});
		assert.equal(response.status, 401);
	});
});

describe('the client credentials grant', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('returns an access token but no refresh token', async () => {
		const tokens = await token(server.base, {grant_type: 'client_credentials', client_id: 'baz'}).then((r) => r.json());
		assert.ok(tokens.access_token);
		assert.ok(!tokens.refresh_token, 'the client credentials grant must not issue a refresh token');
	});

	// nobody authenticates in this grant, so the claim would be meaningless
	test('omits auth_time', async () => {
		const tokens = await token(server.base, {grant_type: 'client_credentials', client_id: 'baz'}).then((r) => r.json());
		assert.ok(!('auth_time' in decodeJwt(tokens.access_token)));
	});

	test('rejects an unknown client', async () => {
		const response = await token(server.base, {grant_type: 'client_credentials', client_id: 'nobody'});
		assert.equal(response.status, 401);
	});
});

describe('the refresh grant', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	const refresh = (refreshToken, jar) =>
		token(server.base, {grant_type: 'refresh_token', client_id: 'baz', refresh_token: refreshToken}, jar);

	// a client refreshing from a server has no cookie to offer
	test('works without a session cookie', async () => {
		const tokens = await getTokens(server.base);
		const response = await refresh(tokens.refresh_token);
		assert.equal(response.status, 200);
		assert.equal(decodeJwt((await response.json()).id_token).sub, 'foo');
	});

	test('keeps auth_time at the original authentication', async () => {
		const first = await getTokens(server.base);
		const authenticatedAt = decodeJwt(first.id_token).auth_time;
		await wait(1100); // the claim only proves anything once the clock has moved on
		const second = await refresh(first.refresh_token).then((response) => response.json());
		const refreshed = decodeJwt(second.id_token);
		assert.ok(refreshed.iat > authenticatedAt, 'the refreshed token should be newer');
		assert.equal(refreshed.auth_time, authenticatedAt);
	});

	test('replaces the refresh token each time', async () => {
		const tokens = await getTokens(server.base);
		const next = await refresh(tokens.refresh_token).then((response) => response.json());
		assert.notEqual(next.refresh_token, tokens.refresh_token);
		assert.equal((await refresh(tokens.refresh_token)).status, 401, 'the superseded token must stop working');
		assert.equal((await refresh(next.refresh_token)).status, 200);
	});

	// an empty value must not match a session that has not been issued a token yet
	test('rejects an empty or missing token', async () => {
		const jar = new CookieJar();
		await approve(server.base, {jar});
		assert.equal((await refresh('', jar)).status, 401);
		assert.equal((await token(server.base, {grant_type: 'refresh_token', client_id: 'baz'}, jar)).status, 401);
	});

	test('rejects a token that was revoked', async () => {
		const tokens = await getTokens(server.base);
		await request(server.base, '/oauth/revoke', {form: {token: tokens.refresh_token}});
		assert.equal((await refresh(tokens.refresh_token)).status, 401);
	});
});

describe('the supporting endpoints', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('userinfo returns the claims of the token subject', async () => {
		const tokens = await getTokens(server.base);
		const claims = await request(server.base, '/userinfo', {
			headers: {Authorization: `Bearer ${tokens.access_token}`},
		}).then((response) => response.json());
		assert.equal(claims.sub, 'foo');
		assert.equal(claims.name, 'Foo');
		assert.ok(!('accessClaims' in claims));
	});

	test('userinfo requires a bearer token', async () => {
		assert.equal((await request(server.base, '/userinfo')).status, 401);
	});

	test('introspection reports a live refresh token', async () => {
		const tokens = await getTokens(server.base);
		const result = await request(server.base, '/introspect', {form: {token: tokens.refresh_token}}).then((r) =>
			r.json()
		);
		assert.equal(result.active, true);
	});

	test('introspection reports an unknown token as inactive', async () => {
		const result = await request(server.base, '/introspect', {form: {token: 'nope'}}).then((r) => r.json());
		assert.equal(result.active, false);
	});

	test('clearing removes the issued sessions', async () => {
		const tokens = await getTokens(server.base);
		assert.equal((await request(server.base, '/api/clear', {method: 'POST'})).status, 200);
		const result = await request(server.base, '/introspect', {form: {token: tokens.refresh_token}}).then((r) =>
			r.json()
		);
		assert.equal(result.active, false);
	});
});
