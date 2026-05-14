// Verify connection pool reuses one TLS+H2 session for many concurrent requests
// (matches Chrome's behavior, no fingerprint cost from repeated handshakes).

const request = require('../../')

;(async () => {
	let handshakes = 0
	const origCreate = request.pool._create.bind(request.pool)
	request.pool._create = (...args) => { handshakes++; return origCreate(...args) }

	// Concurrent against cloudflare (allows many streams).
	const N = 8
	const t0 = Date.now()
	const results = await Promise.all(Array.from({ length: N }, () =>
		request({ url: 'https://www.cloudflare.com/', resolveWithFullResponse: true, simple: false })
	))
	const elapsed = Date.now() - t0
	const allOk = results.every(r => r?.status > 0)
	const pass = handshakes === 1 && allOk
	console.log(`${pass ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'} concurrent reuse: ${handshakes} handshake(s) for ${N} requests in ${elapsed}ms (all ok=${allOk})`)

	// Serial against peet (verify second request also reuses, even though peet is single-shot).
	handshakes = 0
	try {
		await request({ url: 'https://tls.peet.ws/api/all', json: true })
		await request({ url: 'https://tls.peet.ws/api/all', json: true, forever: false })
	} catch (_) {}
	console.log(`${handshakes >= 2 ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'} forever:false bypasses pool (got ${handshakes} fresh)`)

	request.pool.closeAll()
	process.exit(pass ? 0 : 1)
})()
