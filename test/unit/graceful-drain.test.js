// Pool.shutdown drains in-flight requests instead of cancelling them.

const test = require('node:test')
const assert = require('node:assert')
const http2 = require('node:http2')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execSync } = require('node:child_process')

function genCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

test('shutdown waits for in-flight requests then closes', { timeout: 10_000 }, async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => {
		// Delay 300ms before responding so we can call shutdown mid-flight.
		setTimeout(() => { s.respond({ ':status': 200 }); s.end('ok') }, 300)
	})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	const request = require('../../')
	// Send 3 concurrent requests
	const promises = [
		request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false }),
		request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false }),
		request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false }),
	]
	// Begin shutdown ~50ms into the flight — well before the server responds.
	await new Promise((r) => setTimeout(r, 50))
	const shutdownPromise = request.pool.shutdown(5000)

	// All 3 requests must complete successfully (NOT be cancelled).
	const results = await Promise.all(promises)
	assert.strictEqual(results.length, 3)
	for (const r of results) assert.ok(r, 'request returned a body')

	// shutdown must resolve after the in-flight completes.
	await shutdownPromise
	assert.strictEqual(request.pool.connections.size, 0, 'all connections closed after drain')

	server.close()
})

test('shutdown rejects new acquires while draining', { timeout: 10_000 }, async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => { setTimeout(() => { s.respond({ ':status': 200 }); s.end('ok') }, 200) })
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	const request = require('../../')
	// Kick off one in-flight req, then start shutdown.
	const inflight = request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false })
	await new Promise((r) => setTimeout(r, 30))
	const draining = request.pool.shutdown(5000)
	// A new acquire during the drain must be rejected with EPROTO.
	await assert.rejects(
		request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, forever: false }),
		(e) => e.code === 'EPROTO' && /draining/.test(e.message),
	)
	await inflight
	await draining
	server.close()
})
