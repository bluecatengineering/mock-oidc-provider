'use strict';

const {after, before, describe, test} = require('node:test');
const assert = require('node:assert/strict');

const {startServer, CookieJar, request, location, approve} = require('./helpers');

describe('the end session endpoint', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	// the redirect URI is optional, so the provider has to report the outcome itself
	test('reports the logout when no redirect uri was given', async () => {
		const response = await request(server.base, '/oidc/logout');
		assert.equal(response.status, 200);
		assert.match(await response.text(), /Signed out/);
	});

	test('redirects when a redirect uri was given', async () => {
		const query = new URLSearchParams({post_logout_redirect_uri: 'http://localhost/bye'});
		const response = await request(server.base, `/oidc/logout?${query}`);
		assert.equal(response.status, 302);
		assert.equal(response.headers.get('location'), 'http://localhost/bye');
	});

	test('passes the state back to the client', async () => {
		const query = new URLSearchParams({post_logout_redirect_uri: 'http://localhost/bye', state: 'xyz'});
		const response = await request(server.base, `/oidc/logout?${query}`);
		assert.equal(location(response).searchParams.get('state'), 'xyz');
	});

	test('keeps a query string the redirect uri already had', async () => {
		const query = new URLSearchParams({post_logout_redirect_uri: 'http://localhost/bye?a=1', state: 'xyz'});
		const response = await request(server.base, `/oidc/logout?${query}`);
		const target = location(response);
		assert.equal(target.searchParams.get('a'), '1');
		assert.equal(target.searchParams.get('state'), 'xyz');
	});

	test('does not invent a state value', async () => {
		const query = new URLSearchParams({post_logout_redirect_uri: 'http://localhost/bye?a=1'});
		const response = await request(server.base, `/oidc/logout?${query}`);
		assert.equal(response.headers.get('location'), 'http://localhost/bye?a=1');
	});

	test('ends the session even without a redirect uri', async () => {
		const jar = new CookieJar();
		await approve(server.base, {jar});
		assert.ok(jar.get('mock-auth'), 'the login should have started a session');

		await request(server.base, '/oidc/logout', {jar});
		assert.ok(!jar.get('mock-auth'), 'the session cookie should have been expired');

		// with the session gone the provider must ask the user to log in again
		const query = new URLSearchParams({response_type: 'code', client_id: 'baz', redirect_uri: 'http://localhost/cb'});
		const response = await request(server.base, `/authorize?${query}`, {jar});
		assert.equal(response.status, 200);
		assert.match(await response.text(), /<form/);
	});
});

describe('the auth0 style logout endpoint', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('redirects to returnTo', async () => {
		const response = await request(
			server.base,
			`/v2/logout?${new URLSearchParams({returnTo: 'http://localhost/home'})}`
		);
		assert.equal(response.headers.get('location'), 'http://localhost/home');
	});

	// this endpoint has no state parameter, so it must not gain one
	test('ignores a state parameter', async () => {
		const query = new URLSearchParams({returnTo: 'http://localhost/home', state: 'xyz'});
		const response = await request(server.base, `/v2/logout?${query}`);
		assert.equal(response.headers.get('location'), 'http://localhost/home');
	});

	test('reports the logout when returnTo is missing', async () => {
		const response = await request(server.base, '/v2/logout');
		assert.equal(response.status, 200);
	});
});
