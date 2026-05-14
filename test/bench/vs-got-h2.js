// Benchmark: hellojs vs got (HTTP/2 mode) vs got (HTTP/1.1) vs request-promise.
//
// got v14 supports HTTP/2 via {http2: true}. This isolates the HTTP/2 multiplexing
// comparison: both hellojs and got can stream many requests over one h2 connection,
// but the implementations are very different (hellojs uses our custom TLS + node:http2
// over a Duplex; got uses http2-wrapper).

const hello = require('../../')
const rp = require('request-promise')
const https = require('https')

const URL = 'https://www.cloudflare.com/cdn-cgi/trace'
const N = 50

const stats = (arr) => {
	const sorted = [...arr].sort((a, b) => a - b)
	const sum = arr.reduce((a, b) => a + b, 0)
	return {
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

;(async () => {
	const got = (await import('got')).default

	// hellojs runner
	const helloRun = () => hello({ url: URL, resolveWithFullResponse: true, simple: false })

	// got with HTTP/2 forced (uses http2-wrapper, separate session per origin, multiplexes)
	const gotH2 = got.extend({ http2: true, throwHttpErrors: false })
	const gotH2Run = () => gotH2(URL)

	// got HTTP/1.1 (default) for comparison
	const gotH1 = got.extend({ http2: false, throwHttpErrors: false })
	const gotH1Run = () => gotH1(URL)

	// request-promise (h1 only)
	const rpAgent = new https.Agent({ keepAlive: true, maxSockets: 100 })
	const rpRun = () => rp({ url: URL, agent: rpAgent, simple: false, resolveWithFullResponse: true })

	const cold = async (label, run) => {
		const t = await timeOne(run)
		console.log(`  ${label.padEnd(22)} cold = ${t}ms`)
		return t
	}

	const serial = async (label, run, count) => {
		const times = []
		for (let i = 0; i < count; i++) times.push(await timeOne(run))
		const s = stats(times)
		console.log(`  ${label.padEnd(22)} serial-${count}  total=${s.total}ms ${fmt(s)}`)
		return s
	}

	const concurrent = async (label, run, count) => {
		const t0 = Date.now()
		const times = await Promise.all(Array.from({ length: count }, () => timeOne(run)))
		const wall = Date.now() - t0
		const s = stats(times)
		console.log(`  ${label.padEnd(22)} concurr-${count} wall=${wall}ms ${fmt(s)}`)
		return { ...s, wall }
	}

	console.log('Target:', URL)
	console.log('N =', N)
	console.log()

	console.log('--- COLD SINGLE (full handshake + 1 request) ---')
	await cold('hellojs (h2)',           helloRun)
	await cold('got (h2)',               gotH2Run)
	await cold('got (h1)',               gotH1Run)
	await cold('request-promise (h1)',   rpRun)
	console.log()

	console.log('--- SERIAL ' + N + ' (steady-state, keep-alive) ---')
	// Warm each connection so we measure steady state
	await Promise.all([helloRun(), gotH2Run(), gotH1Run(), rpRun()])

	const hSer  = await serial('hellojs (h2)',         helloRun, N)
	const g2Ser = await serial('got (h2)',             gotH2Run, N)
	const g1Ser = await serial('got (h1)',             gotH1Run, N)
	const rpSer = await serial('request-promise (h1)', rpRun,    N)
	console.log()

	console.log('--- CONCURRENT ' + N + ' (multiplex/fanout) ---')
	const hCon  = await concurrent('hellojs (h2)',         helloRun, N)
	const g2Con = await concurrent('got (h2)',             gotH2Run, N)
	const g1Con = await concurrent('got (h1)',             gotH1Run, N)
	const rpCon = await concurrent('request-promise (h1)', rpRun,    N)
	console.log()

	console.log('--- SUMMARY ---')
	const row = (lbl, vals) => console.log(lbl.padEnd(22) + vals.map(v => String(v).padEnd(14)).join(''))
	row('', ['hellojs', 'got h2', 'got h1', 'rp h1'])
	row('serial mean (ms)',     [hSer.mean.toFixed(1), g2Ser.mean.toFixed(1), g1Ser.mean.toFixed(1), rpSer.mean.toFixed(1)])
	row('serial p95 (ms)',      [hSer.p95, g2Ser.p95, g1Ser.p95, rpSer.p95])
	row('concurrent wall (ms)', [hCon.wall, g2Con.wall, g1Con.wall, rpCon.wall])
	row('throughput (req/s)',   [(N*1000/hCon.wall).toFixed(0), (N*1000/g2Con.wall).toFixed(0), (N*1000/g1Con.wall).toFixed(0), (N*1000/rpCon.wall).toFixed(0)])

	hello.pool.closeAll()
	rpAgent.destroy()
	process.exit(0)
})().catch(e => { console.error(e); process.exit(1) })
