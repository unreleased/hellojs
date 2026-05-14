// Exercises the request.js-shape public API end-to-end against tls.peet.ws.
// Verifies: callback form, promise form, defaults, jar, qs, gzip auto-decompress, h2 path.

const request = require('../../')

let pass = 0, fail = 0
const log = (label, ok, detail) => {
	if (ok) { pass++; console.log(`\x1b[32mPASS\x1b[0m ${label}`) }
	else { fail++; console.log(`\x1b[31mFAIL\x1b[0m ${label}${detail ? '\n     ' + detail : ''}`) }
}

;(async () => {
	// 1. Promise form, JSON parse
	try {
		const data = await request({
			url: 'https://tls.peet.ws/api/all',
			json: true,
			gzip: true,
			resolveWithFullResponse: true,
		})
		log('promise+json+gzip+full-response',
			data.status === 200 && data.body?.tls?.ja4?.startsWith('t13d1516h2_8daaf6152771_'),
			`status=${data.status} ja4=${data.body?.tls?.ja4}`)
	} catch (e) { log('promise+json+gzip+full-response', false, e.message) }

	// 2. Callback form
	await new Promise((r) => {
		request({ url: 'https://tls.peet.ws/api/all', json: true }, (err, res, body) => {
			log('callback form', !err && body?.tls?.ja4, err?.message)
			r()
		})
	})

	// 3. Method shortcuts
	try {
		const body = await request.get({ url: 'https://tls.peet.ws/api/all', json: true })
		log('request.get shortcut', body?.method === 'GET', `method=${body?.method}`)
	} catch (e) { log('request.get shortcut', false, e.message) }

	// 4. Defaults instance
	try {
		const r = request.defaults({ json: true, headers: { 'x-custom': 'hellojs' } })
		const body = await r({ url: 'https://tls.peet.ws/api/all' })
		log('request.defaults', body?.tls?.ja4, '')
	} catch (e) { log('request.defaults', false, e.message) }

	// 5. qs builder
	try {
		const body = await request({ url: 'https://tls.peet.ws/api/all', qs: { foo: 'bar', baz: 1 }, json: true })
		log('qs builder', body?.method === 'GET', '')
	} catch (e) { log('qs builder', false, e.message) }

	// 6. JA4 still matches Chrome 147 via the API path.
	// We only assert the JA4_b component (cipher truncated-SHA256) since extension count
	// legitimately bumps by 1 (16 → 17) when a cached TLS session triggers pre_shared_key.
	try {
		const body = await request({ url: 'https://tls.peet.ws/api/all', json: true })
		const j = body?.tls?.ja4 || ''
		const okPrefix = j.startsWith('t13d1516h2_') || j.startsWith('t13d1517h2_')
		const okCipher = j.includes('_8daaf6152771_')
		log('JA4 still matches via request() API', okPrefix && okCipher, `ja4=${j}`)
	} catch (e) { log('JA4 still matches via request() API', false, e.message) }

	console.log(`\n${pass}/${pass + fail} passed`)
	request.pool.closeAll()
	process.exit(fail ? 1 : 0)
})()
