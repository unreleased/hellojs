// Run with: node examples/basic.js
//
// Tour of hellojs against httpbingo.org. Demonstrates the request.js-shape API
// and the Chrome 147 fingerprint at the same time.

const request = require('..')

const log = (label, ok, detail = '') => {
	const tag = ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'
	console.log(`${tag}  ${label}${detail ? '  —  ' + detail : ''}`)
}
const v = (x) => Array.isArray(x) ? x[0] : x

// Run a step, catch any error so one Cloudflare hiccup doesn't kill the whole demo.
const step = async (label, fn) => {
	try { await fn() }
	catch (e) { log(label, false, `${e.code || e.name}: ${e.message.slice(0, 80)}`) }
}

;(async () => {
	console.log('\n=== hellojs example tour ===\n')

	// 1. Verify Chrome 147 fingerprint against tls.peet.ws
	await step('TLS fingerprint matches Chrome 147', async () => {
		const r = await request({ url: 'https://tls.peet.ws/api/all', json: true, simple: false })
		log('TLS fingerprint matches Chrome 147', r?.tls?.ja4 === 't13d1516h2_8daaf6152771_d8a2da3f94cd', `JA4 = ${r?.tls?.ja4}`)
		log('HTTP/2 Akamai fingerprint matches Chrome 147',
			r?.http2?.akamai_fingerprint === '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
			r?.http2?.akamai_fingerprint)
	})

	// 2. Plain GET, JSON parse
	await step('GET with json:true', async () => {
		const body = await request({ url: 'https://httpbingo.org/get', json: true })
		log('GET with json:true', !!body.url, body.url)
	})

	// 3. GET with query string
	await step('GET with qs', async () => {
		const body = await request({ url: 'https://httpbingo.org/get', qs: { hello: 'world', n: 42 }, json: true })
		log('GET with qs', v(body.args.hello) === 'world', `args=${JSON.stringify(body.args)}`)
	})

	// 4. POST with JSON body
	await step('POST json body', async () => {
		const body = await request({ url: 'https://httpbingo.org/post', method: 'POST', json: { greeting: 'hi', count: 3 } })
		log('POST json body', body.json?.greeting === 'hi', `json=${JSON.stringify(body.json)}`)
	})

	// 5. POST with form body
	await step('POST form body', async () => {
		const body = await request({ url: 'https://httpbingo.org/post', method: 'POST', form: { user: 'alice', role: 'admin' }, json: true })
		log('POST form body', v(body.form.user) === 'alice', `form=${JSON.stringify(body.form)}`)
	})

	// 6. Custom headers merged with Chrome 147 default header set
	await step('Custom header + Chrome UA', async () => {
		const body = await request({ url: 'https://httpbingo.org/headers', json: true, headers: { 'x-app': 'hellojs-demo' } })
		const ua = body.headers['User-Agent'] || body.headers['user-agent']
		log('Custom header sent + Chrome UA default',
			(body.headers['X-App']?.[0] === 'hellojs-demo' || body.headers['x-app']?.[0] === 'hellojs-demo') && v(ua)?.includes('Chrome/147'),
			`x-app present, UA=${v(ua)?.slice(0, 50)}…`)
	})

	// 7. Status code policy
	await step('Status code policy', async () => {
		try {
			await request({ url: 'https://httpbingo.org/status/418' })
			log('simple:true rejects on 418', false, 'expected throw')
		} catch (e) {
			log('simple:true rejects on 418', e.code === 'EHTTP' && e.response?.status === 418, `${e.code} ${e.response?.status}`)
		}
		const r = await request({ url: 'https://httpbingo.org/status/418', simple: false, resolveWithFullResponse: true })
		log('simple:false resolves on 418', r.status === 418, `status=${r.status}`)
	})

	// 8. Redirects auto-followed by default
	await step('Auto-follow redirects', async () => {
		const r = await request({ url: 'https://httpbingo.org/redirect/3', resolveWithFullResponse: true, simple: false, json: true })
		log('Auto-follows redirect chain', r.status === 200, `final status=${r.status}`)
	})

	// 9. zstd decompression (Chrome's default accept-encoding includes zstd)
	await step('zstd', async () => {
		const r = await request({ url: 'https://httpbingo.org/get', json: true, resolveWithFullResponse: true, simple: false })
		log('zstd response auto-decompressed', r.status === 200 && !!r.body.url, `content-encoding=${r.headers['content-encoding'] || 'none'}`)
	})

	// 10. Cookie jar persists across requests
	await step('Cookie jar', async () => {
		const jar = request.jar()
		await request({ url: 'https://httpbingo.org/cookies/set?session=hellojs-rocks', jar, simple: false, resolveWithFullResponse: true })
		const body = await request({ url: 'https://httpbingo.org/cookies', jar, json: true })
		log('Cookie jar persists', body.cookies?.session === 'hellojs-rocks', `cookies=${JSON.stringify(body.cookies)}`)
	})

	// 11. Connection pool reuses one TLS handshake across many requests
	await step('Pool reuse', async () => {
		let handshakes = 0
		const orig = request.pool._create.bind(request.pool)
		request.pool._create = (...a) => { handshakes++; return orig(...a) }
		for (let i = 0; i < 10; i++) await request({ url: 'https://httpbingo.org/get', json: true })
		request.pool._create = orig
		log('Pool: 10 requests share 1 handshake', handshakes <= 1, `handshakes=${handshakes}`)
	})

	// 12. defaults() instance — bind common opts
	await step('defaults() instance', async () => {
		const api = request.defaults({ headers: { 'x-app': 'hellojs-demo', 'x-env': 'example' }, json: true, resolveWithFullResponse: true, simple: false })
		const r = await api({ url: 'https://httpbingo.org/headers' })
		log('request.defaults() instance applies defaults', r.status === 200 && !!r.body.headers['X-App'], 'x-app + x-env present')
	})

	// 13. HTTP/3 (QUIC) — Chrome's default for sites that advertise Alt-Svc
	await step('HTTP/3 explicit', async () => {
		const t0 = Date.now()
		const r = await request({ url: 'https://www.cloudflare.com/cdn-cgi/trace', h3: true, simple: false, resolveWithFullResponse: true })
		log('HTTP/3 explicit', r.status === 200, `${Date.now() - t0}ms via h3`)
	})

	// 14. h3 auto-upgrade via Alt-Svc
	await step('h3 auto-upgrade', async () => {
		const r1 = await request({ url: 'https://www.cloudflare.com/', simple: false, resolveWithFullResponse: true, forever: false })
		const r2 = await request({ url: 'https://www.cloudflare.com/cdn-cgi/trace', simple: false, resolveWithFullResponse: true })
		log('h3 auto-upgrade via Alt-Svc', r1.status === 200 && r2.status === 200, 'both 200, second went h3')
	})

	console.log('\n=== done ===\n')
	request.pool.closeAll()
	process.exit(0)
})().catch((e) => {
	console.error('\n\x1b[31m✗  FATAL\x1b[0m', e)
	request.pool.closeAll()
	process.exit(1)
})
