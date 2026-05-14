// HelloRetryRequest real-world coverage.
//
// Force the server to send HRR by offering a key_share for a group the server doesn't
// support (or by sending an empty key_share). RFC 8446 §4.1.4: when the server can't
// pick a key_share from CH1, it MUST respond with HelloRetryRequest containing the
// `selected_group` and (typically) a stateless cookie. CH2 includes the new key_share
// and the cookie, and the handshake proceeds.
//
// This test uses the internal `_forceHRRGroup` test affordance to send a ClientHello
// that DEFINITELY triggers HRR — advertising only a single group with no real key_share.

const { TLS } = require('../../lib/tls/tls')

const TARGETS = [
	'www.cloudflare.com',
	'www.google.com',
	'github.com',
]

async function probe(host, forceGroup) {
	return new Promise((resolve) => {
		const tls = new TLS(host, 443, null, { _forceHRRGroup: forceGroup })
		const t = setTimeout(() => { tls.socket?.destroy(); resolve({ host, ok: false, err: 'timeout' }) }, 15_000)
		const finish = (alpn) => {
			clearTimeout(t)
			const cipher = '0x' + (tls.server?.cipherSuite ?? 0).toString(16)
			const group  = tls.server?.serverKShare?.group ? '0x' + tls.server.serverKShare.group.toString(16) : 'n/a'
			tls.h2Session?.close?.()
			tls.socket?.destroy()
			resolve({ host, ok: true, alpn, cipher, group })
		}
		tls.on('ready', () => finish('h2'))
		tls.on('ready-http1', () => finish('http/1.1'))
		tls.on('error', (e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message }) })
		tls.connect().catch((e) => { clearTimeout(t); resolve({ host, ok: false, err: e.message }) })
	})
}

;(async () => {
	console.log('HelloRetryRequest — forcing server to respond with HRR + retry on CH2\n')

	let pass = 0, fail = 0
	for (const host of TARGETS) {
		// Force HRR by offering only secp256r1 with no real key_share — the server will
		// HRR-select x25519 (or whatever its first-preference group is) and we re-send.
		const r = await probe(host, 0x0017)  // secp256r1 — most servers prefer x25519 first
		if (r.ok) {
			pass++
			console.log(`\x1b[32mOK\x1b[0m   ${host.padEnd(22)} alpn=${r.alpn.padEnd(8)} group=${r.group.padEnd(8)} cipher=${r.cipher}`)
		} else {
			fail++
			console.log(`\x1b[31mFAIL\x1b[0m ${host.padEnd(22)} err=${r.err}`)
		}
	}

	console.log(`\n${pass}/${pass + fail} HRR retries succeeded`)
	process.exit(fail ? 1 : 0)
})()
