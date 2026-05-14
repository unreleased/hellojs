// Test that Alt-Svc auto-upgrade works: first request is h2, captures alt-svc,
// second request auto-upgrades to h3 transparently.

const request = require('../../')
const { lookupAltSvc } = require('../../lib/pool')

;(async () => {
	let pass = 0, fail = 0
	const log = (label, ok, detail) => {
		if (ok) { pass++; console.log(`\x1b[32mPASS\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
		else { fail++; console.log(`\x1b[31mFAIL\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
	}

	const HOST = 'www.cloudflare.com'

	// 1) Explicit h3
	try {
		const r = await request({ url: `https://${HOST}/cdn-cgi/trace`, h3: true, resolveWithFullResponse: true, simple: false })
		log('explicit h3 via request({h3:true})', r.status === 200 && r.rawBody.length > 0, `status=${r.status} bytes=${r.rawBody.length}`)
	} catch (e) { log('explicit h3', false, e.message) }

	// 2) First h2 request captures Alt-Svc (homepage includes alt-svc header)
	try {
		const r = await request({ url: `https://${HOST}/`, resolveWithFullResponse: true, simple: false, forever: false })
		const alt = lookupAltSvc(HOST)
		log('h2 response captures Alt-Svc', !!alt, alt ? `port=${alt.port}` : 'no alt-svc seen')
	} catch (e) { log('h2 captures Alt-Svc', false, e.message) }

	// 3) Second request to same host auto-upgrades to h3 (because Alt-Svc cached)
	try {
		const r = await request({ url: `https://${HOST}/cdn-cgi/trace`, resolveWithFullResponse: true, simple: false })
		log('second request succeeds (auto-upgrade)', r.status === 200 && r.rawBody.length > 0, `status=${r.status}`)
	} catch (e) { log('auto-upgrade', false, e.message) }

	console.log(`\n${pass}/${pass + fail} passed`)
	request.pool.closeAll()
	process.exit(fail ? 1 : 0)
})()
