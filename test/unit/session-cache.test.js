// TLS session cache: in-memory + persistent file round-trip.

const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

function makeSession(seed = 0) {
	return {
		ticketLifetime: 7200,
		ticketAgeAdd: 0x12345678,
		ticketNonce: Buffer.from([seed]),
		ticket: Buffer.from(`ticket-${seed}-bytes-go-here-padding-padding`),
		maxEarlyDataSize: 0xffffffff,
		issuedAt: Date.now(),
		expiresAt: Date.now() + 3600_000,
	}
}

test('put + take returns the same session', () => {
	const cache = require('../../lib/tls/session-cache')
	cache.clear()
	cache.put('example.com', makeSession(1))
	const got = cache.take('example.com')
	assert.ok(got)
	assert.strictEqual(got.ticketLifetime, 7200)
	assert.strictEqual(got.ticket.toString(), 'ticket-1-bytes-go-here-padding-padding')
})

test('cache evicts beyond MAX_PER_HOST (4)', () => {
	const cache = require('../../lib/tls/session-cache')
	cache.clear()
	for (let i = 0; i < 10; i++) cache.put('h.example', makeSession(i))
	assert.strictEqual(cache.size('h.example'), 4)
})

test('expired tickets are skipped on take', () => {
	const cache = require('../../lib/tls/session-cache')
	cache.clear()
	cache.put('e.example', { ...makeSession(1), expiresAt: Date.now() - 1000 })
	assert.strictEqual(cache.take('e.example'), null)
})

test('persistent cache survives an enable+flush+reload cycle', () => {
	// Use a separate, isolated cache instance by deleting require cache + re-requiring.
	const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hjsc-')), 'sessions.json')

	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	let cache = require('../../lib/tls/session-cache')
	cache.enablePersistence({ path: tmp })
	cache.clear()
	cache.put('persist.example', makeSession(42))
	cache.flush()
	assert.ok(fs.existsSync(tmp), 'persistence file should be written')

	// New process simulation: drop the module from cache, then re-require with the same file.
	delete require.cache[require.resolve('../../lib/tls/session-cache')]
	cache = require('../../lib/tls/session-cache')
	cache.enablePersistence({ path: tmp })
	const got = cache.take('persist.example')
	assert.ok(got)
	assert.strictEqual(got.ticket.toString(), 'ticket-42-bytes-go-here-padding-padding')
	assert.ok(Buffer.isBuffer(got.ticket), 'ticket should round-trip as Buffer')

	cache.clear()
	fs.rmSync(path.dirname(tmp), { recursive: true, force: true })
})
