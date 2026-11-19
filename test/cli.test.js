'use strict';

const {describe, test} = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const {join} = require('node:path');

const {startServer, getTokens} = require('./helpers');

const serverPath = join(__dirname, '..', 'src', 'server.js');

const run = (...args) => spawnSync(process.execPath, [serverPath, ...args], {encoding: 'utf8', timeout: 10000});

describe('the command line', () => {
	for (const args of [['--help'], ['-h']]) {
		test(`prints the usage and exits with ${args[0]}`, () => {
			const {status, stderr} = run(...args);
			assert.equal(status, 1);
			assert.match(stderr, /Usage:/);
		});
	}

	test('rejects an unknown option', () => {
		const {status, stderr} = run('--bogus');
		assert.equal(status, 1);
		assert.match(stderr, /--bogus/);
		assert.match(stderr, /Usage:/);
	});

	test('rejects an option without a value', () => {
		const {status, stderr} = run('--port');
		assert.equal(status, 1);
		assert.match(stderr, /Usage:/);
	});

	test('does not take the next option as a value', () => {
		const {status, stderr} = run('-p', '-s', '9000');
		assert.equal(status, 1);
		assert.match(stderr, /Usage:/);
	});

	test('rejects a positional argument', () => {
		const {status, stderr} = run('extra');
		assert.equal(status, 1);
		assert.match(stderr, /Usage:/);
	});

	test('requires the certificate and key together', () => {
		const {status, stderr} = run('--cert', 'cert.pem');
		assert.equal(status, 1);
		assert.match(stderr, /certificate and key/);
	});

	test('accepts the --name=value form', async () => {
		const server = await startServer(['--ttl=60']);
		try {
			const {expires_in: expiresIn} = await getTokens(server.base);
			assert.equal(expiresIn, 60);
		} finally {
			await server.stop();
		}
	});

	test('prefers the command line over the environment', async () => {
		const server = await startServer(['-t', '90'], {TTL: '30'});
		try {
			const {expires_in: expiresIn} = await getTokens(server.base);
			assert.equal(expiresIn, 90);
		} finally {
			await server.stop();
		}
	});

	test('falls back to the environment', async () => {
		const server = await startServer([], {TTL: '30'});
		try {
			const {expires_in: expiresIn} = await getTokens(server.base);
			assert.equal(expiresIn, 30);
		} finally {
			await server.stop();
		}
	});
});
