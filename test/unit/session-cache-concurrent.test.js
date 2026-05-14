// Session cache: persistent file is safe across concurrent writers.

const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { fork } = require('node:child_process')

function makeSession(seed) {
	return {
		ticketLifetime: 7200,
		ticketAgeAdd: 0x12345678,
		ticketNonce: Buffer.from([seed & 0xff]),
		ticket: Buffer.from(`ticket-${seed}-bytes`),
		maxEarlyDataSize: 0,
		issuedAt: Date.now(),
		expiresAt: Date.now() + 3600_000,
	}
}

test('concurrent writers do not clobber each other (in-process)', () => {
	const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hjcc-')), 'sessions.json')

	// Use TWO separate require-cache slots to simulate two independent processes.
	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	const a = require('../../lib/tls/session-cache')
	a.enablePersistence({ path: tmp })
	a.clear()
	a.put('host-a.example', makeSession(1))
	a.flush()

	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	const b = require('../../lib/tls/session-cache')
	b.enablePersistence({ path: tmp })
	// b should LOAD a's ticket via enablePersistence; now put its own.
	b.put('host-b.example', makeSession(2))
	b.flush()

	// Now reload from a third "process" — should see BOTH writes.
	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	const c = require('../../lib/tls/session-cache')
	c.enablePersistence({ path: tmp })
	const tA = c.take('host-a.example')
	const tB = c.take('host-b.example')
	assert.ok(tA, 'host-a ticket should survive concurrent write')
	assert.ok(tB, 'host-b ticket should survive concurrent write')
	assert.strictEqual(tA.ticket.toString(), 'ticket-1-bytes')
	assert.strictEqual(tB.ticket.toString(), 'ticket-2-bytes')

	fs.rmSync(path.dirname(tmp), { recursive: true, force: true })
})

test('a stale lock (older than 30s) is auto-removed', async () => {
	const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hjsl-')), 'sessions.json')
	fs.mkdirSync(path.dirname(tmp), { recursive: true })

	// Drop a fake stale lock.
	fs.writeFileSync(tmp + '.lock', String(99999))
	// Backdate its mtime to 60s ago.
	const past = (Date.now() - 60_000) / 1000
	fs.utimesSync(tmp + '.lock', past, past)

	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	const cache = require('../../lib/tls/session-cache')
	cache.enablePersistence({ path: tmp })
	cache.clear()
	cache.put('host.example', makeSession(7))
	cache.flush()

	assert.ok(fs.existsSync(tmp), 'cache file should exist (stale lock was reclaimed)')
	assert.ok(!fs.existsSync(tmp + '.lock'), 'lock file should be released after flush')

	fs.rmSync(path.dirname(tmp), { recursive: true, force: true })
})

test('two real subprocess writers merge instead of clobbering', { timeout: 10_000 }, async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcp-'))
	const tmp = path.join(dir, 'sessions.json')

	const worker = path.join(dir, 'w.js')
	fs.writeFileSync(worker, `
		const cache = require('${path.resolve(__dirname, '../../lib/tls/session-cache.js')}');
		const host = process.argv[2];
		const tag  = process.argv[3];
		cache.enablePersistence({ path: '${tmp}' });
		// 100 puts to stress the lock
		for (let i = 0; i < 100; i++) {
			cache.put(host, {
				ticketLifetime: 7200,
				ticketAgeAdd: 0,
				ticketNonce: Buffer.from([i & 0xff]),
				ticket: Buffer.from(tag + '-' + i),
				maxEarlyDataSize: 0,
				issuedAt: Date.now(),
				expiresAt: Date.now() + 3600_000,
			});
		}
		cache.flush();
	`)

	await Promise.all([
		new Promise((r) => fork(worker, ['host-a.example', 'A']).on('exit', r)),
		new Promise((r) => fork(worker, ['host-b.example', 'B']).on('exit', r)),
		new Promise((r) => fork(worker, ['host-c.example', 'C']).on('exit', r)),
	])

	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	const cache = require('../../lib/tls/session-cache')
	cache.enablePersistence({ path: tmp })
	assert.ok(cache.peek('host-a.example'), 'A survived')
	assert.ok(cache.peek('host-b.example'), 'B survived')
	assert.ok(cache.peek('host-c.example'), 'C survived')

	fs.rmSync(dir, { recursive: true, force: true })
})
