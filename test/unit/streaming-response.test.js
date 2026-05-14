// opts.stream returns a Readable that delivers chunks as they arrive (no buffer).

const test = require('node:test')
const assert = require('node:assert')
const http2 = require('node:http2')
const tls = require('node:tls')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { execSync } = require('node:child_process')
const { after } = require('node:test')

after(() => { require('../../').pool.closeAll() })

function genServerCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsrv-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

test('opts.stream resolves with a Readable that yields chunks progressively', { timeout: 10_000 }, async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert, allowHTTP1: false })
	server.on('stream', (stream, hdrs) => {
		stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' })
		// Write 16 chunks of 8KB so the client receives them piecewise.
		let n = 0
		const tick = () => {
			if (n >= 16) { stream.end(); return }
			stream.write(crypto.randomBytes(8192))
			n++
			setImmediate(tick)
		}
		tick()
	})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	try {
		const request = require('../../')
		// localhost cert is not in trust store, so we must disable cert validation.
		const stream = await request({
			url: `https://127.0.0.1:${port}/`,
			stream: true,
			verifyTLS: false,
		})

		let bytes = 0
		let chunkCount = 0
		await new Promise((resolve, reject) => {
			stream.on('data', (c) => { bytes += c.length; chunkCount++ })
			stream.on('end', resolve)
			stream.on('error', reject)
		})

		assert.strictEqual(bytes, 16 * 8192, 'all bytes received')
		assert.ok(chunkCount >= 2, `expected multiple progressive chunks, got ${chunkCount}`)
	} finally {
		server.close()
	}
})

test('opts.stream + resolveWithFullResponse exposes status, headers, body Readable', { timeout: 10_000 }, async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 201, 'x-hello': 'world' })
		stream.end('payload')
	})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	try {
		const request = require('../../')
		const res = await request({
			url: `https://127.0.0.1:${port}/`,
			stream: true,
			resolveWithFullResponse: true,
			verifyTLS: false,
		})
		assert.strictEqual(res.statusCode, 201)
		assert.strictEqual(res.headers['x-hello'], 'world')
		assert.ok(res.body && typeof res.body.pipe === 'function')
		const chunks = []
		for await (const c of res.body) chunks.push(c)
		assert.strictEqual(Buffer.concat(chunks).toString(), 'payload')
	} finally {
		server.close()
	}
})
