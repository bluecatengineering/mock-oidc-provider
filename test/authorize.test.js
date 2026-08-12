'use strict';

const {after, before, describe, test} = require('node:test');
const assert = require('node:assert/strict');

const {startServer, CookieJar, request, location, approve} = require('./helpers');

describe('the authorization endpoint', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('shows the login form when there is no session', async () => {
		const response = await request(server.base, '/authorize?response_type=code&client_id=baz&redirect_uri=http://cb');
		assert.equal(response.status, 200);
		assert.match(await response.text(), /<form/);
	});

	test('rejects a missing response type instead of failing', async () => {
		const response = await request(server.base, '/authorize');
		assert.equal(response.status, 400);
	});

	test('rejects a repeated parameter instead of failing', async () => {
		const response = await request(server.base, '/authorize?response_type=code&response_type=code');
		assert.equal(response.status, 400);
	});

	test('rejects an unsupported response type', async () => {
		const response = await request(server.base, '/authorize?response_type=token&client_id=baz');
		assert.equal(response.status, 400);
	});

	test('rejects an unsupported code challenge method', async () => {
		const response = await request(server.base, '/authorize?response_type=code&code_challenge_method=RS256');
		assert.equal(response.status, 400);
	});

	test('escapes the client id written into the page', async () => {
		const clientId = '<img src=x onerror=alert(1)>';
		const query = new URLSearchParams({response_type: 'code', client_id: clientId, redirect_uri: 'http://cb'});
		const body = await request(server.base, `/authorize?${query}`).then((response) => response.text());
		assert.ok(!body.includes(clientId), 'the raw client id must not reach the page');
		assert.match(body, /&lt;img src=x onerror=alert\(1\)&gt;/);
	});

	test('escapes a value that would otherwise close the inline script', async () => {
		const query = new URLSearchParams({
			response_type: 'code',
			client_id: 'baz',
			redirect_uri: 'http://cb',
			state: '</script><script>alert(1)</script>',
		});
		const body = await request(server.base, `/authorize?${query}`).then((response) => response.text());
		assert.ok(!body.includes('</script><script>'), 'the script element must not be closed early');
		assert.match(body, /\\u003c\/script>/);
	});

	test('issues a code directly when a session already exists', async () => {
		const jar = new CookieJar();
		await approve(server.base, {jar});
		const query = new URLSearchParams({response_type: 'code', client_id: 'baz', redirect_uri: 'http://localhost/cb'});
		const response = await request(server.base, `/authorize?${query}`, {jar});
		assert.equal(response.status, 302);
		assert.ok(location(response).searchParams.get('code'));
	});
});

describe('the login form submission', () => {
	let server;
	before(async () => (server = await startServer()));
	after(() => server.stop());

	test('redirects back with a code and the state', async () => {
		const {response} = await approve(server.base, {state: 'xyz'});
		assert.equal(response.status, 302);
		const target = location(response);
		assert.equal(target.origin + target.pathname, 'http://localhost/cb');
		assert.ok(target.searchParams.get('code'));
		assert.equal(target.searchParams.get('state'), 'xyz');
	});

	test('omits the state when the client did not send one', async () => {
		const {response} = await approve(server.base);
		assert.ok(!location(response).searchParams.has('state'), 'must not invent a state value');
	});

	test('reports a denial with the state so the client can correlate it', async () => {
		const response = await request(
			server.base,
			`/api/form?${new URLSearchParams({error: 'true', redirect_uri: 'http://localhost/cb', state: 'xyz'})}`
		);
		const target = location(response);
		assert.equal(target.searchParams.get('error'), 'access_denied');
		assert.equal(target.searchParams.get('state'), 'xyz');
	});

	test('reports an unknown subject rather than creating a broken session', async () => {
		const response = await request(
			server.base,
			`/api/form?${new URLSearchParams({sub: 'nobody', redirect_uri: 'http://localhost/cb', state: 'xyz'})}`
		);
		const target = location(response);
		assert.equal(target.searchParams.get('error'), 'invalid_request');
		assert.equal(target.searchParams.get('state'), 'xyz');
		assert.ok(!target.searchParams.has('code'));
	});

	test('refuses a request that has nowhere to redirect to', async () => {
		const response = await request(server.base, '/api/form?sub=foo');
		assert.equal(response.status, 400);
	});

	test('refuses a repeated redirect uri', async () => {
		const response = await request(server.base, '/api/form?sub=foo&redirect_uri=http://a&redirect_uri=http://b');
		assert.equal(response.status, 400);
	});
});
