// Smoke test h3 handshake against several public h3 endpoints.
const { QuicConnection } = require('../../lib/h3/connection')
const { H3Client } = require('../../lib/h3/h3')

const targets = [
	{ host: 'cloudflare-quic.com', path: '/' },
	{ host: 'www.cloudflare.com', path: '/cdn-cgi/trace' },
	{ host: 'www.google.com', path: '/' },
	{ host: 'cloud.google.com', path: '/' },
	{ host: 'quic.aiortc.org', path: '/' },
]

async function tryOne({ host, path }) {
	return new Promise((resolve) => {
		const conn = new QuicConnection(host, 443)
		const t = setTimeout(() => { conn.close(); resolve({ host, ok: false, err: 'timeout' }) }, 8000)
		conn.on('error', (e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message.slice(0, 80) }) })
		conn.on('ready', async () => {
			try {
				const t0 = Date.now()
				const h3 = new H3Client(conn)
				const res = await Promise.race([
					h3.request({ method: 'GET', path, host }),
					new Promise((_, rej) => setTimeout(() => rej(new Error('req timeout')), 6000)),
				])
				clearTimeout(t)
				conn.close()
				resolve({ host, ok: true, status: res.status, bytes: res.body.length, server: res.headers.server, ms: Date.now() - t0 })
			} catch (e) { clearTimeout(t); conn.close(); resolve({ host, ok: false, err: e.message.slice(0, 80) }) }
		})
		conn.connect().catch((e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message.slice(0, 80) }) })
	})
}

;(async () => {
	// Serial — concurrent UDP handshakes tickle a packet-reordering bug
	// in our naive UDP recv loop (out-of-order Initial/Handshake packets
	// across many sockets). Serial works reliably.
	const results = []
	for (const t of targets) results.push(await tryOne(t))
	let pass = 0, fail = 0
	for (const r of results) {
		if (r.ok) {
			console.log(`\x1b[32mOK\x1b[0m   ${r.host.padEnd(22)} status=${r.status} bytes=${r.bytes} server="${r.server}" t=${r.ms}ms`)
			pass++
		} else {
			console.log(`\x1b[31mFAIL\x1b[0m ${r.host.padEnd(22)} err=${r.err}`)
			fail++
		}
	}
	console.log(`\n${pass}/${pass + fail} servers OK`)
	process.exit(fail ? 1 : 0)
})()
