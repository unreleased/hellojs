// Benchmark: hellojs vs request-promise vs Node https.
//
// Scenarios:
//   1. Cold single GET — full handshake + 1 request
//   2. Serial 20 GETs — measures keep-alive / connection reuse
//   3. Concurrent 20 GETs — measures multiplexing
//
// Target: a small JSON endpoint on Cloudflare (cdn-cgi/trace) which is fast,
// keep-alive friendly, and supports h2 (for hellojs).

const hello = require('../../')
const rp = require('request-promise')
const https = require('https')

const URL = 'https://www.cloudflare.com/cdn-cgi/trace'
const N = 50

const stats = (arr) => {
	const sorted = [...arr].sort((a, b) => a - b)
	const sum = arr.reduce((a, b) => a + b, 0)
	return {
		n: arr.length,
		min: sorted[0],
		p50: sorted[Math.floor(arr.length * 0.5)],
		p95: sorted[Math.floor(arr.length * 0.95)] || sorted[arr.length - 1],
		max: sorted[arr.length - 1],
		mean: sum / arr.length,
		total: sum,
	}
}
const fmt = (s) => `min=${s.min}ms p50=${s.p50}ms p95=${s.p95}ms max=${s.max}ms mean=${s.mean.toFixed(1)}ms`

async function timeOne(fn) {
	const t0 = Date.now()
	await fn()
	return Date.now() - t0
}

// hellojs runner
const helloAgent = hello.defaults({ resolveWithFullResponse: true, simple: false })
const helloFresh = (forever = true) => helloAgent({ url: URL, forever })

// request-promise with a keep-alive https.Agent
const rpAgent = new https.Agent({ keepAlive: true, maxSockets: 30 })
const rpRunOpts = { url: URL, agent: rpAgent, simple: false, resolveWithFullResponse: true }
const rpRun = () => rp(rpRunOpts)

// Node https direct, with keep-alive (no abstraction overhead — control)
function nodeHttpsGet() {
	return new Promise((resolve, reject) => {
		const r = https.request(URL, { method: 'GET', agent: rpAgent }, (res) => {
			let len = 0
			res.on('data', (c) => { len += c.length })
			res.on('end', () => resolve(len))
		})
		r.on('error', reject)
		r.end()
	})
}

const cold = async (label, run) => {
	const cold1 = await timeOne(run)
	console.log(`  ${label.padEnd(20)} cold-single = ${cold1}ms`)
	return cold1
}

const serial = async (label, run) => {
	const times = []
	for (let i = 0; i < N; i++) times.push(await timeOne(run))
	const s = stats(times)
	console.log(`  ${label.padEnd(20)} serial-${N}  total=${s.total}ms  ${fmt(s)}`)
	return s
}

const concurrent = async (label, run) => {
	const t0 = Date.now()
	const times = await Promise.all(Array.from({ length: N }, () => timeOne(run)))
	const total = Date.now() - t0
	const s = stats(times)
	console.log(`  ${label.padEnd(20)} concurr-${N} wall=${total}ms  ${fmt(s)}`)
	return { ...s, wall: total }
}

;(async () => {
	console.log('Target:', URL)
	console.log('N =', N)
	console.log()

	console.log('--- COLD SINGLE (full handshake + 1 request) ---')
	await cold('hellojs',          () => helloFresh(false))   // forever:false to force fresh
	await cold('request-promise',  () => rp({ ...rpRunOpts, forever: false, agent: undefined }))
	await cold('node https',       nodeHttpsGet)
	console.log()

	console.log('--- SERIAL ' + N + ' (keep-alive / connection reuse) ---')
	// Warm one connection first to be fair (so we measure steady-state, not handshake)
	await helloFresh()
	await rpRun()
	await nodeHttpsGet()

	const helloSerial = await serial('hellojs',         helloFresh)
	const rpSerial    = await serial('request-promise', rpRun)
	const httpsSerial = await serial('node https',      nodeHttpsGet)
	console.log()

	console.log('--- CONCURRENT ' + N + ' (multiplexing / pool fanout) ---')
	const helloConc = await concurrent('hellojs',         helloFresh)
	const rpConc    = await concurrent('request-promise', rpRun)
	const httpsConc = await concurrent('node https',      nodeHttpsGet)
	console.log()

	console.log('--- SUMMARY ---')
	const tbl = [
		['scenario', 'hellojs', 'request-promise', 'node https', 'winner'],
		['serial mean',       helloSerial.mean.toFixed(1) + 'ms', rpSerial.mean.toFixed(1) + 'ms',    httpsSerial.mean.toFixed(1) + 'ms',
			[helloSerial.mean, rpSerial.mean, httpsSerial.mean].indexOf(Math.min(helloSerial.mean, rpSerial.mean, httpsSerial.mean))],
		['serial total',      helloSerial.total + 'ms',           rpSerial.total + 'ms',              httpsSerial.total + 'ms', ''],
		['concurrent wall',   helloConc.wall + 'ms',              rpConc.wall + 'ms',                 httpsConc.wall + 'ms', ''],
	]
	for (const r of tbl) {
		console.log(r.map((x, i) => i === 4 && typeof x === 'number' ? ['hellojs','request-promise','node https'][x] : String(x).padEnd(18)).join(''))
	}

	hello.pool.closeAll()
	rpAgent.destroy()
	process.exit(0)
})().catch(e => { console.error(e); process.exit(1) })
