// Basic httpbin usage — exercises common request.js patterns end-to-end.
//
// Target: httpbingo.org (modern Go-based httpbin, TLS 1.3 + h2 + zstd).
// httpbin.org is TLS 1.2 only and we don't support that. Same endpoints, same response shape.

const request = require('../../')
const { clearAltSvc } = require('../../lib/pool')

const BASE = 'https://httpbingo.org'
let pass = 0, fail = 0
const log = (label, ok, detail) => {
	if (ok) { pass++; console.log(`\x1b[32mPASS\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
	else { fail++; console.log(`\x1b[31mFAIL\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
}

const opts = (overrides = {}) => ({ simple: false, ...overrides })

;(async () => {
	clearAltSvc()
	console.log(`Target: ${BASE}\n`)

	// 1. Simple GET, JSON response
	try {
		const body = await request({ ...opts(), url: `${BASE}/get`, json: true })
		log('GET /get returns JSON with url + headers',
			body?.url?.includes('/get') && body?.headers,
			`url=${body?.url}`)
	} catch (e) { log('GET /get', false, e.message) }

	// 2. GET with query string via opts.qs
	const v = (x) => Array.isArray(x) ? x[0] : x
	try {
		const body = await request({ ...opts(), url: `${BASE}/get`, qs: { foo: 'bar', n: 42 }, json: true })
		log('GET with qs builder', v(body?.args?.foo) === 'bar' && String(v(body?.args?.n)) === '42',
			`args=${JSON.stringify(body?.args)}`)
	} catch (e) { log('GET with qs', false, e.message) }

	// 3. Custom headers echoed back
	try {
		const body = await request({ ...opts(), url: `${BASE}/headers`, headers: { 'x-hellojs-test': '147' }, json: true })
		// httpbin lowercases + multivalues
		const echoed = body?.headers?.['X-Hellojs-Test'] || body?.headers?.['x-hellojs-test']
		log('Custom header echoed', echoed && (Array.isArray(echoed) ? echoed[0] === '147' : echoed === '147'),
			`got=${JSON.stringify(echoed)}`)
	} catch (e) { log('custom header', false, e.message) }

	// 4. POST with json body
	try {
		const body = await request({ ...opts(), url: `${BASE}/post`, method: 'POST', json: { hello: 'world', n: 1 } })
		log('POST with json body', body?.json?.hello === 'world' && body?.json?.n === 1,
			`json=${JSON.stringify(body?.json)}`)
	} catch (e) { log('POST json', false, e.message) }

	// 5. POST with form body
	try {
		const body = await request({ ...opts(), url: `${BASE}/post`, method: 'POST', form: { name: 'jack', age: '30' }, json: true })
		log('POST with form body', v(body?.form?.name) === 'jack' && v(body?.form?.age) === '30',
			`form=${JSON.stringify(body?.form)}`)
	} catch (e) { log('POST form', false, e.message) }

	// 6. Status code handling — 418 with simple:true rejects
	try {
		await request({ url: `${BASE}/status/418` })
		log('simple:true rejects on 418', false, 'should have thrown')
	} catch (e) {
		log('simple:true rejects on 418', e.code === 'EHTTP' && e.response?.status === 418, `code=${e.code} status=${e.response?.status}`)
	}

	// 7. Status code with simple:false resolves
	try {
		const r = await request({ ...opts(), url: `${BASE}/status/418`, resolveWithFullResponse: true })
		log('simple:false resolves on 418', r.status === 418, `status=${r.status}`)
	} catch (e) { log('simple:false 418', false, e.message) }

	// 8. Redirects followed by default
	try {
		const r = await request({ ...opts(), url: `${BASE}/redirect/2`, json: true, resolveWithFullResponse: true })
		log('follows redirects (3 hops)', r.status === 200, `final status=${r.status}`)
	} catch (e) { log('redirects', false, e.message) }

	// 9. followRedirect:false leaves 302
	try {
		const r = await request({ ...opts(), url: `${BASE}/redirect/1`, followRedirect: false, resolveWithFullResponse: true })
		log('followRedirect:false stops at 302', r.status >= 300 && r.status < 400 && !!r.headers.location,
			`status=${r.status} loc=${r.headers.location}`)
	} catch (e) { log('no follow', false, e.message) }

	// 10. Gzip auto-decompress
	try {
		const body = await request({ ...opts(), url: `${BASE}/gzip`, gzip: true, json: true })
		log('gzip auto-decompresses', body?.gzipped === true, `gzipped=${body?.gzipped}`)
	} catch (e) { log('gzip', false, e.message) }

	// 11. Cookie jar persists across requests
	try {
		const jar = request.jar()
		// Set a cookie via /cookies/set redirect chain
		await request({ ...opts(), url: `${BASE}/cookies/set?testcookie=hellojs147`, jar, resolveWithFullResponse: true, followRedirect: true })
		// Now check jar
		const body = await request({ ...opts(), url: `${BASE}/cookies`, jar, json: true })
		const cookieValue = body?.cookies?.testcookie
		// nghttp2's httpbin returns cookies as plain strings or arrays of strings depending on version
		const matches = cookieValue === 'hellojs147' || (Array.isArray(cookieValue) && cookieValue[0] === 'hellojs147')
		log('cookie jar persists', matches, `got=${JSON.stringify(body?.cookies)}`)
	} catch (e) { log('cookie jar', false, e.message) }

	// 12. User-agent default is Chrome 147 UA
	try {
		const body = await request({ ...opts(), url: `${BASE}/user-agent`, json: true })
		const ua = body?.['user-agent'] || body?.user_agent
		log('default UA is Chrome 147', typeof ua === 'string' && ua.includes('Chrome/147'), `ua=${ua?.slice(0, 60)}`)
	} catch (e) { log('user-agent', false, e.message) }

	// 13. Pool reuse — 5 sequential requests should reuse one connection
	try {
		let handshakes = 0
		const orig = request.pool._create.bind(request.pool)
		request.pool._create = (...args) => { handshakes++; return orig(...args) }
		for (let i = 0; i < 5; i++) await request({ ...opts(), url: `${BASE}/get`, json: true })
		request.pool._create = orig
		log('pool reuses connection across 5 reqs', handshakes <= 1, `handshakes=${handshakes}`)
	} catch (e) { log('pool reuse', false, e.message) }

	console.log(`\n${pass}/${pass + fail} passed`)
	request.pool.closeAll()
	process.exit(fail ? 1 : 0)
})()
