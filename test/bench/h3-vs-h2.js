// Benchmark h3 vs h2 (cold + warm steady-state).
const request = require('../../')
const N = 10
const stats = (arr) => {
	const sorted = [...arr].sort((a, b) => a - b)
	const sum = arr.reduce((a, b) => a + b, 0)
	return { min: sorted[0], p50: sorted[Math.floor(arr.length * 0.5)], p95: sorted[Math.floor(arr.length * 0.95)] || sorted[arr.length - 1], mean: sum / arr.length, total: sum }
}
const fmt = (s) => `min=${s.min}ms p50=${s.p50}ms p95=${s.p95}ms mean=${s.mean.toFixed(1)}ms`
const timeOne = async (fn) => { const t0 = Date.now(); await fn(); return Date.now() - t0 }
const URL = 'https://www.cloudflare.com/cdn-cgi/trace'

;(async () => {
	const got = (await import('got')).default
	const gotH2 = got.extend({ http2: true, throwHttpErrors: false })

	const helloH2 = () => request({ url: URL, h3: false, resolveWithFullResponse: true, simple: false })
	const helloH3 = () => request({ url: URL, h3: true,  resolveWithFullResponse: true, simple: false })
	const goth2   = () => gotH2(URL)

	console.log('Target:', URL, 'N =', N)
	console.log()

	// Cold: each library's first request
	console.log('--- COLD (1 req including handshake) ---')
	console.log(`  hellojs h2           cold = ${await timeOne(helloH2)}ms`)
	console.log(`  hellojs h3           cold = ${await timeOne(helloH3)}ms`)
	console.log(`  got h2               cold = ${await timeOne(goth2)}ms`)

	console.log()
	console.log(`--- SERIAL ${N} (warm reuse) ---`)
	for (const [label, fn] of [['hellojs h2', helloH2], ['hellojs h3', helloH3], ['got h2', goth2]]) {
		const times = []
		for (let i = 0; i < N; i++) times.push(await timeOne(fn))
		console.log(`  ${label.padEnd(20)} total=${stats(times).total}ms  ${fmt(stats(times))}`)
	}

	request.pool.closeAll()
	process.exit(0)
})().catch(e => { console.error('ERR:', e.message); process.exit(1) })
