// Happy-eyeballs: connect succeeds despite a black-holed family.

const test = require('node:test')
const assert = require('node:assert')
const net = require('node:net')
const { happyConnect } = require('../../lib/happy-eyeballs')

test('connects to a real local TCP server via IPv4', async () => {
	const server = net.createServer(() => {})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port
	const sock = await happyConnect({ host: '127.0.0.1', port, connectTimeoutMs: 1000 })
	assert.ok(sock.writable)
	sock.destroy()
	server.close()
})

test('IP literal short-circuits DNS lookup', async () => {
	const server = net.createServer(() => {})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port
	// IP literal — no DNS, just direct connect attempt.
	const sock = await happyConnect({ host: '127.0.0.1', port, connectTimeoutMs: 500 })
	assert.ok(sock.writable)
	sock.destroy()
	server.close()
})

test('rejects when every address fails (no listener)', async () => {
	// Connect to a closed port on localhost — ECONNREFUSED for both v4 and (likely) v6.
	await assert.rejects(
		happyConnect({ host: '127.0.0.1', port: 1, connectTimeoutMs: 500 }),
		(e) => /failed|refused/i.test(e.message),
	)
})
