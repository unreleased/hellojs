// Smoke test: handshake against a variety of real servers.
// Confirms TLS layer survives the diversity of cipher / group / cert-compression / ALPN choices.

const { TLS } = require('../../lib/tls/tls')

const targets = [
	'tls.peet.ws',
	'www.cloudflare.com',
	'www.google.com',
	'www.amazon.com',
	'github.com',
	'httpbin.org',
]

async function tryOne(host) {
	return new Promise((resolve) => {
		const tls = new TLS(host, 443)
		const t = setTimeout(() => { tls.socket?.destroy(); resolve({ host, ok: false, err: 'timeout' }) }, 10000)
		const finish = (alpn) => {
			clearTimeout(t)
			tls.h2Session?.close?.()
			tls.socket?.destroy()
			const isTls12 = !!tls.tls12
			const group = isTls12 ? 'n/a(1.2)' : ('0x' + tls.server.serverKShare.group.toString(16))
			resolve({ host, ok: true, alpn, group, cipher: '0x' + tls.server.cipherSuite.toString(16), version: isTls12 ? '1.2' : '1.3' })
		}
		tls.on('ready', () => finish('h2'))
		tls.on('ready-http1', () => finish('http/1.1'))
		tls.on('error', (e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message }) })
		tls.connect().catch((e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message }) })
	})
}

;(async () => {
	const results = await Promise.all(targets.map(tryOne))
	let pass = 0, fail = 0
	for (const r of results) {
		if (r.ok) {
			console.log(`\x1b[32mOK\x1b[0m   ${r.host.padEnd(22)} tls=${r.version} alpn=${r.alpn.padEnd(8)} group=${r.group.padEnd(8)} cipher=${r.cipher}`)
			pass++
		} else {
			console.log(`\x1b[31mFAIL\x1b[0m ${r.host.padEnd(22)} err=${r.err}`)
			fail++
		}
	}
	console.log(`\n${pass}/${pass + fail} servers OK`)
	process.exit(fail ? 1 : 0)
})()
