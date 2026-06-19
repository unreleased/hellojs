// HTTP/1.1 response parsing over keep-alive connections.
//
// Regression for the bug where performH1 parsed the response only inside
// `transport.once('end', onEnd)`, and 'end' fires only when the peer closes the socket. HTTP/1.1
// defaults to keep-alive (hellojs sends no Connection header), so a conformant server holds the
// socket open and the request hung until the response timeout. These tests stand up a real TLS
// server that forces the http/1.1 ALPN and DELIBERATELY keeps the socket open, then assert the
// request RESOLVES (the old code rejects with ETIMEDOUT).

const test = require('node:test')
const assert = require('node:assert')
const tls = require('node:tls')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execSync } = require('node:child_process')
const { after } = require('node:test')

const request = require('../../')

after(() => request.pool.closeAll())

function genServerCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsh1-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

// Start a raw TLS server that negotiates http/1.1 and invokes `onRequest(socket, method, head)`
// for each complete request head it receives on a connection (so a single kept-alive socket can
// serve several requests). Tracks live sockets + connection count for assertions/cleanup.
function startH1Server(onRequest) {
	const { key, cert } = genServerCert()
	const sockets = new Set()
	const server = tls.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (socket) => {
		server.connectionCount++
		sockets.add(socket)
		socket.on('error', () => {})
		socket.on('close', () => sockets.delete(socket))
		let acc = Buffer.alloc(0)
		socket.on('data', (chunk) => {
			acc = Buffer.concat([acc, chunk])
			let idx
			while ((idx = acc.indexOf('\r\n\r\n')) >= 0) {
				const head = acc.subarray(0, idx).toString('latin1')
				acc = acc.subarray(idx + 4)
				onRequest(socket, head.split(' ')[0], head)
			}
		})
	})
	server.connectionCount = 0
	server._sockets = sockets
	return server
}

async function withServer(onRequest, fn) {
	const server = startH1Server(onRequest)
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port
	try {
		return await fn(port, server)
	} finally {
		request.pool.closeAll()
		for (const s of server._sockets) s.destroy()
		await new Promise((r) => server.close(r))
	}
}

test('keep-alive + Content-Length resolves without waiting for socket close', { timeout: 8000 }, async () => {
	const body = 'hello keep-alive'
	await withServer((sock) => {
		// No close(): the socket stays open exactly as a keep-alive server would leave it.
		sock.write(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n${body}`)
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 200)
		assert.strictEqual(res.body.toString(), body)
	})
})

test('keep-alive + chunked (streamed) resolves with the decoded body', { timeout: 8000 }, async () => {
	await withServer((sock) => {
		sock.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n')
		// Deliver chunks across separate writes to exercise incremental framing.
		const parts = ['5\r\nhello\r\n', '6\r\n world\r\n', '0\r\n\r\n']
		let i = 0
		const tick = () => { if (i < parts.length) { sock.write(parts[i++]); setImmediate(tick) } }
		tick()
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 200)
		assert.strictEqual(res.body.toString(), 'hello world')
	})
})

test('keep-alive connection is reused across sequential requests', { timeout: 8000 }, async () => {
	let n = 0
	await withServer((sock) => {
		const body = `resp-${++n}`
		sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n${body}`)
	}, async (port, server) => {
		const r1 = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000 })
		const r2 = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000 })
		assert.strictEqual(r1.toString(), 'resp-1')
		assert.strictEqual(r2.toString(), 'resp-2')
		assert.strictEqual(server.connectionCount, 1, 'both requests should share one pooled keep-alive connection')
	})
})

test('concurrent requests to one h1 origin get their own distinct responses', { timeout: 8000 }, async () => {
	let n = 0
	await withServer((sock) => {
		const body = `response-${++n}`
		// Delay slightly to widen the race window between concurrent requests.
		setTimeout(() => sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n${body}`), 15)
	}, async (port) => {
		const url = `https://127.0.0.1:${port}/`
		const bodies = (await Promise.all(
			Array.from({ length: 5 }, () => request({ url, verifyTLS: false, timeout: 3000 })),
		)).map((b) => b.toString())
		// Each request must see a unique body — no cross-contamination from a shared connection.
		assert.strictEqual(new Set(bodies).size, 5, `expected 5 distinct responses, got ${JSON.stringify(bodies)}`)
	})
})

test('keep-alive 204 No Content resolves with an empty body', { timeout: 8000 }, async () => {
	await withServer((sock) => {
		sock.write('HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n')
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 204)
		assert.strictEqual(res.body.length, 0)
	})
})

test('keep-alive HEAD with Content-Length resolves without reading a body', { timeout: 8000 }, async () => {
	await withServer((sock, method) => {
		assert.strictEqual(method, 'HEAD')
		// Content-Length describes the would-be GET body; a HEAD response must carry no body.
		sock.write('HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n')
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, method: 'HEAD', verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 200)
		assert.strictEqual(res.headers['content-length'], '1234')
		assert.strictEqual(res.body.length, 0)
	})
})

test('Connection: close still parses correctly', { timeout: 8000 }, async () => {
	const body = 'goodbye'
	await withServer((sock) => {
		sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`)
		sock.end()
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 200)
		assert.strictEqual(res.body.toString(), body)
	})
})

test('connection-close-delimited body (no Content-Length / chunked) resolves on close', { timeout: 8000 }, async () => {
	const body = 'eof-delimited-payload'
	await withServer((sock) => {
		sock.write(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n${body}`)
		sock.end()  // body is delimited by the socket closing
	}, async (port) => {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, timeout: 3000, resolveWithFullResponse: true })
		assert.strictEqual(res.statusCode, 200)
		assert.strictEqual(res.body.toString(), body)
	})
})
