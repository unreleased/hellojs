// Fingerprint regression test: drives our TLS class directly into its built-in
// http2 session and asserts JA4 / Akamai fingerprint vs the captured Chrome 147 fixture.

const fs = require('fs')
const path = require('path')
const { TLS } = require('../../lib/tls/tls')

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/chrome147-peet.json'), 'utf8'))

;(async () => {
	const tls = new TLS('tls.peet.ws', 443)
	const json = await new Promise((resolve, reject) => {
		const t = setTimeout(() => reject(new Error('timeout')), 15000)
		tls.on('ready', () => {
			const req = tls.h2Session.request({
				':method': 'GET',
				':authority': 'tls.peet.ws',
				':scheme': 'https',
				':path': '/api/all',
				'sec-ch-ua': '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"macOS"',
				'upgrade-insecure-requests': '1',
				'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
				'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
				'sec-fetch-site': 'none',
				'sec-fetch-mode': 'navigate',
				'sec-fetch-user': '?1',
				'sec-fetch-dest': 'document',
				'accept-encoding': 'gzip, deflate, br, zstd',
				'accept-language': 'en-US,en;q=0.9,es;q=0.8',
				'priority': 'u=0, i',
			}, { endStream: true, weight: 256, exclusive: true, parent: 0 })
			const chunks = []
			req.on('data', c => chunks.push(c))
			req.on('end', () => {
				clearTimeout(t)
				const buf = Buffer.concat(chunks)
				try {
					const j = JSON.parse(buf.toString('utf8'))
					tls.h2Session.close()
					resolve(j)
				} catch (e) { reject(e) }
			})
			req.on('error', e => { clearTimeout(t); reject(e) })
			req.end()
		})
		tls.on('ready-http1', () => reject(new Error('server picked http/1.1 instead of h2')))
		tls.connect()
	})

	const checks = []
	const expect = (name, actual, expected) => checks.push({ name, ok: actual === expected, actual, expected })
	const expectSet = (name, actual, expected) => {
		const a = JSON.stringify([...actual].sort())
		const e = JSON.stringify([...expected].sort())
		checks.push({ name, ok: a === e, actual: a, expected: e })
	}
	const expectList = (name, actual, expected) => {
		const a = JSON.stringify(actual)
		const e = JSON.stringify(expected)
		checks.push({ name, ok: a === e, actual: a, expected: e })
	}

	expect('http_version', json.http_version, fixture.http_version)
	expect('tls_version_negotiated', json.tls?.tls_version_negotiated, fixture.tls.tls_version_negotiated)
	expect('ja4', json.tls?.ja4, fixture.tls.ja4)
	expect('akamai_fingerprint', json.http2?.akamai_fingerprint, fixture.http2.akamai_fingerprint)

	const norm = s => s.replace(/0x[0-9a-f]{4}/i, 'GREASE')
	expectList('ciphers', json.tls.ciphers.map(norm), fixture.tls.ciphers.map(norm))
	expectSet('extensions (set)', json.tls.extensions.map(e => norm(e.name)), fixture.tls.extensions.map(e => norm(e.name)))
	expectList('signature_algorithms', json.tls.extensions.find(e => e.name.startsWith('signature_algorithms')).signature_algorithms,
		fixture.tls.extensions.find(e => e.name.startsWith('signature_algorithms')).signature_algorithms)
	expectList('supported_groups', json.tls.extensions.find(e => e.name.startsWith('supported_groups')).supported_groups.map(norm),
		fixture.tls.extensions.find(e => e.name.startsWith('supported_groups')).supported_groups.map(norm))
	expectList('supported_versions', json.tls.extensions.find(e => e.name.startsWith('supported_versions')).versions.map(norm),
		fixture.tls.extensions.find(e => e.name.startsWith('supported_versions')).versions.map(norm))

	// HTTP/2 sent frames — order, types, header order
	const headersFrame = json.http2?.sent_frames?.find(f => f.frame_type === 'HEADERS')
	const fxHeadersFrame = fixture.http2.sent_frames.find(f => f.frame_type === 'HEADERS')
	if (headersFrame && fxHeadersFrame) {
		expectList('h2 HEADERS flags', headersFrame.flags.sort(), fxHeadersFrame.flags.sort())
		// Header *order* (we expect to send them in a Chrome-matching order)
		const ourHeaderNames = headersFrame.headers.map(h => h.split(':', 1)[0] || h.split(': ', 1)[0])
		const fxHeaderNames = fxHeadersFrame.headers.map(h => h.split(':', 1)[0] || h.split(': ', 1)[0])
		// Compare order, but the fixture has 'referer' from real navigation — exclude it
		const fxFiltered = fxHeaderNames.filter(n => n !== 'referer')
		expectList('h2 header order', ourHeaderNames, fxFiltered)
	}

	let pass = 0, fail = 0
	for (const c of checks) {
		const tag = c.ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'
		console.log(`${tag} ${c.name}`)
		if (!c.ok) {
			console.log(`     expected: ${c.expected}`)
			console.log(`     actual:   ${c.actual}`)
			fail++
		} else { pass++ }
	}
	console.log(`\n${pass}/${pass + fail} checks passed`)
	process.exit(fail ? 1 : 0)
})().catch(err => {
	console.error('FATAL:', err)
	process.exit(2)
})
