'use strict';

const {spawn} = require('node:child_process');
const {createServer} = require('node:net');
const {join} = require('node:path');

const serverPath = join(__dirname, '..', 'src', 'server.js');

// binding to port 0 lets the operating system hand out a port that is free right now
const findPort = () =>
	new Promise((resolve, reject) => {
		const probe = createServer();
		probe.once('error', reject);
		probe.listen(0, () => {
			const {port} = probe.address();
			probe.close(() => resolve(port));
		});
	});

const waitUntilReady = async (base, child, stderr) => {
	for (let attempt = 0; attempt < 100; ++attempt) {
		if (child.exitCode !== null) {
			throw new Error(`server exited with code ${child.exitCode}\n${stderr()}`);
		}
		try {
			await fetch(`${base}/.well-known/openid-configuration`);
			return;
		} catch {
			await new Promise((resolve) => setTimeout(resolve, 50));
		}
	}
	throw new Error(`server did not become ready\n${stderr()}`);
};

/** Starts the provider on a free port; the returned `stop` resolves once the process is gone. */
const startServer = async (args = [], env = {}) => {
	const port = await findPort();
	const child = spawn(process.execPath, [serverPath, '--port', String(port), ...args], {
		env: {...process.env, ...env},
		stdio: ['ignore', 'ignore', 'pipe'],
	});
	let errorOutput = '';
	child.stderr.setEncoding('utf8');
	child.stderr.on('data', (chunk) => (errorOutput += chunk));

	const base = `http://localhost:${port}`;
	try {
		await waitUntilReady(base, child, () => errorOutput);
	} catch (error) {
		child.kill();
		throw error;
	}
	return {
		base,
		stderr: () => errorOutput,
		stop: () =>
			new Promise((resolve) => {
				child.once('exit', resolve);
				child.kill();
			}),
	};
};

/** Minimal cookie store, since fetch does not keep cookies between calls. */
class CookieJar {
	constructor() {
		this.cookies = new Map();
	}

	update(response) {
		for (const cookie of response.headers.getSetCookie()) {
			const [pair] = cookie.split(';');
			const separator = pair.indexOf('=');
			const name = pair.slice(0, separator).trim();
			const value = pair.slice(separator + 1).trim();
			// an empty value is how the server expires the cookie
			if (value) this.cookies.set(name, value);
			else this.cookies.delete(name);
		}
	}

	get(name) {
		return this.cookies.get(name);
	}

	header() {
		return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
	}
}

/** Performs a request without following redirects, optionally carrying cookies. */
const request = async (base, path, {method = 'GET', form, headers = {}, jar} = {}) => {
	const init = {method, redirect: 'manual', headers: {...headers}};
	if (form) {
		init.method = 'POST';
		init.body = new URLSearchParams(form);
	}
	if (jar) {
		const cookie = jar.header();
		if (cookie) init.headers.Cookie = cookie;
	}
	const response = await fetch(`${base}${path}`, init);
	if (jar) jar.update(response);
	return response;
};

const location = (response) => new URL(response.headers.get('location'));

const decodeJwt = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));

/** Approves the login form, returning the authorization code handed back to the client. */
const approve = async (base, {jar, ...query} = {}) => {
	const params = new URLSearchParams({sub: 'foo', redirect_uri: 'http://localhost/cb', ...query});
	const response = await request(base, `/api/form?${params}`, {jar});
	return {response, code: location(response).searchParams.get('code')};
};

/** Runs a full authorization code exchange and returns the parsed token response. */
const getTokens = async (base, {jar, ...query} = {}) => {
	const {code} = await approve(base, {jar, ...query});
	const response = await request(base, '/oauth/token', {
		form: {grant_type: 'authorization_code', client_id: 'baz', code},
		jar,
	});
	return response.json();
};

module.exports = {startServer, CookieJar, request, location, decodeJwt, approve, getTokens};
