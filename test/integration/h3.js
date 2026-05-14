// HTTP/3 integration test: open a real QUIC connection against a public h3 server,
// complete the TLS 1.3-in-QUIC handshake, send a GET, decode the response.

const { QuicConnection } = require('../../lib/h3/connection')
const { H3Client } = require('../../lib/h3/h3')

const HOST = process.env.H3_HOST || 'cloudflare-quic.com'
const PATH = process.env.H3_PATH || '/'

;(async () => {
	const conn = new QuicConnection(HOST, 443)
	const t0 = Date.now()

	const ready = new Promise((resolve, reject) => {
		const t = setTimeout(() => reject(new Error('h3 handshake timeout')), 15000)
		conn.on('ready', () => { clearTimeout(t); resolve() })
		conn.on('error', (e) => { clearTimeout(t); reject(e) })
	})

	try {
		await conn.connect()
		console.log('UDP socket bound, ClientHello sent')
		await ready
		console.log(`HANDSHAKE OK in ${Date.now() - t0}ms (alpn=${conn.alpn})`)

		const h3 = new H3Client(conn)
		const res = await Promise.race([
			h3.request({ method: 'GET', path: PATH, host: HOST }),
			new Promise((_, rej) => setTimeout(() => rej(new Error('request timeout')), 10000)),
		])
		console.log('STATUS:', res.status)
		console.log('HEADERS:', JSON.stringify(res.headers, null, 2))
		console.log('BODY:', res.body.length, 'bytes')
		console.log('Body preview:', res.body.subarray(0, 300).toString('utf8'))
		conn.close()
		process.exit(0)
	} catch (e) {
		console.error('FAILED:', e.message)
		conn.close()
		process.exit(1)
	}
})()
