// Per-phase timeouts — connect/tlsHandshake/response.

const test = require('node:test')
const assert = require('node:assert')
const net = require('node:net')
const { Pool } = require('../../lib/pool')

test('connect timeout fires when TCP connect hangs (route to a sinkhole IP)', async () => {
	// 240.0.0.1 is in TEST-NET-3 / reserved; routers drop the SYN, so connect hangs forever.
	const pool = new Pool()
	const t0 = Date.now()
	await assert.rejects(
		pool.acquire({ host: '240.0.0.1', port: 443, timeouts: { connect: 200 } }),
		(e) => e.code === 'ETIMEDOUT' && /TCP connect timed out/.test(e.message),
	)
	const dt = Date.now() - t0
	assert.ok(dt < 1000, `expected fail within ~200ms, took ${dt}ms`)
})

test('handshake timeout fires when peer accepts TCP but never speaks TLS', async () => {
	// Spin up a TCP server that accepts connections and does nothing — TLS handshake will hang.
	const server = net.createServer(() => { /* silent */ })
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	const pool = new Pool()
	try {
		const t0 = Date.now()
		await assert.rejects(
			pool.acquire({ host: '127.0.0.1', port, timeouts: { tlsHandshake: 200 }, verifyTLS: false }),
			(e) => e.code === 'ETIMEDOUT' && /TLS handshake timed out/.test(e.message),
		)
		const dt = Date.now() - t0
		assert.ok(dt < 1000, `expected handshake fail within ~200ms, took ${dt}ms`)
	} finally {
		server.close()
	}
})
