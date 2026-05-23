// Pool per-host slot semaphore: waiter queue drains under rejection and high concurrency.

const test = require('node:test')
const assert = require('node:assert')
const { Pool } = require('../../lib/pool')

test('semaphore: each acquire+release cycle returns slot to pool (no leak)', async () => {
	const pool = new Pool({ maxPerHost: 2 })

	// Manually drive _acquireSlot / _releaseSlot to test the primitive without TLS.
	await pool._acquireSlot('h.example', 443)
	await pool._acquireSlot('h.example', 443)
	assert.strictEqual(pool.hostState.get('h:example'.replace('h:example', 'h.example:443'))?.count ?? pool.hostState.get('h.example:443')?.count, 2)

	pool._releaseSlot('h.example', 443)
	pool._releaseSlot('h.example', 443)

	// Both released → the host entry should be cleaned up entirely.
	assert.strictEqual(pool.hostState.get('h.example:443'), undefined)
})

test('semaphore: waiters in the queue resume when a slot is released', async () => {
	const pool = new Pool({ maxPerHost: 1 })
	await pool._acquireSlot('h.example', 443)

	// Queue up three waiters
	const w1 = pool._acquireSlot('h.example', 443)
	const w2 = pool._acquireSlot('h.example', 443)
	const w3 = pool._acquireSlot('h.example', 443)

	let resolvedCount = 0
	const onR = () => resolvedCount++
	w1.then(onR); w2.then(onR); w3.then(onR)

	// None should have resolved yet
	await new Promise((r) => setImmediate(r))
	assert.strictEqual(resolvedCount, 0, 'no waiter should resolve while slot is held')

	// Release one → exactly one waiter resumes
	pool._releaseSlot('h.example', 443)
	await new Promise((r) => setImmediate(r))
	assert.strictEqual(resolvedCount, 1)

	// Release again → next waiter
	pool._releaseSlot('h.example', 443)
	await new Promise((r) => setImmediate(r))
	assert.strictEqual(resolvedCount, 2)

	pool._releaseSlot('h.example', 443)
	await new Promise((r) => setImmediate(r))
	assert.strictEqual(resolvedCount, 3)

	// Drain the held permits and assert the host entry is gone.
	pool._releaseSlot('h.example', 443)
	pool._releaseSlot('h.example', 443)
	pool._releaseSlot('h.example', 443)
	assert.strictEqual(pool.hostState.get('h.example:443'), undefined)
})

test('semaphore: rejected acquire releases its slot (no waiter leak)', async () => {
	const pool = new Pool({ maxPerHost: 1 })

	// 240.0.0.1 is unroutable in this harness; depending on host networking it may fail
	// during connect timeout or earlier with an unreachable-network error.
	await assert.rejects(
		pool.acquire({ host: '240.0.0.1', port: 443, timeouts: { connect: 100 } }),
		(e) => e.code === 'ETIMEDOUT' || e.code === 'ENETUNREACH',
	)
	// The slot should be released on failure — a fresh acquire to the same host must succeed
	// immediately rather than block.
	await assert.rejects(
		pool.acquire({ host: '240.0.0.1', port: 443, timeouts: { connect: 100 } }),
		(e) => e.code === 'ETIMEDOUT' || e.code === 'ENETUNREACH',
	)
	// Should now have NO held slots
	assert.strictEqual(pool.hostState.get('240.0.0.1:443'), undefined)
})

test('forceFresh can still populate the pool for later reuse', async () => {
	const pool = new Pool({ maxPerHost: 2 })
	let creates = 0
	pool._create = async () => {
		creates++
		return {
			closed: false,
			close() { this.closed = true },
			canIssueRequest() { return !this.closed },
			markUsed() {},
		}
	}

	const first = await pool.acquire({ host: 'cache.example', port: 443, forceFresh: true, cacheConnection: true })
	const second = await pool.acquire({ host: 'cache.example', port: 443 })
	assert.strictEqual(second, first)
	assert.strictEqual(creates, 1)
	first.close('done')
})
