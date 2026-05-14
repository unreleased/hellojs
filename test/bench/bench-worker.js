// Subprocess worker: run one client through cold + warm + concurrent + memory phases.
// Reads BENCH_CLIENT, BENCH_TARGET, BENCH_PORT from env; prints JSON to stdout.

const path = require('node:path')

const CLIENT = process.env.BENCH_CLIENT
const TARGET = process.env.BENCH_TARGET
const PORT   = parseInt(process.env.BENCH_PORT || '443', 10)
const WARM_REPS = parseInt(process.env.BENCH_WARM_REPS || '30', 10)
const CONCURRENT = parseInt(process.env.BENCH_CONCURRENT || '50', 10)

// Each adapter is `(url, opts?) => Promise<bodyBytes>`. We share one client/agent
// across the cold + warm + concurrent phases so connection reuse is measured.

async function makeAdapter(name) {
	if (name === 'hellojs') {
		const request = require('../..')
		return {
			fn: async (url) => {
				const r = await request({ url, verifyTLS: false, resolveWithFullResponse: true })
				return r.body.length || r.rawBody?.length || 0
			},
			cleanup: () => request.pool.closeAll(),
		}
	}
	if (name === 'node-https') {
		const https = require('node:https')
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		return {
			fn: (url) => new Promise((resolve, reject) => {
				const req = https.get(url, { agent, rejectUnauthorized: false }, (res) => {
					let total = 0
					res.on('data', (c) => total += c.length)
					res.on('end', () => resolve(total))
				})
				req.on('error', reject)
			}),
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'node-http2') {
		const http2 = require('node:http2')
		// Pool sessions by origin so multiple requests reuse the same connection.
		const sessions = new Map()
		const getSession = (url) => {
			const u = new URL(url)
			const key = u.origin
			let s = sessions.get(key)
			if (s && !s.destroyed && !s.closed) return s
			s = http2.connect(u.origin, { rejectUnauthorized: false })
			sessions.set(key, s)
			s.on('error', () => {})
			return s
		}
		return {
			fn: (url) => new Promise((resolve, reject) => {
				const u = new URL(url)
				const s = getSession(url)
				const req = s.request({ ':method': 'GET', ':path': u.pathname + u.search, ':authority': u.host, ':scheme': 'https' })
				let total = 0
				req.on('data', (c) => total += c.length)
				req.on('end', () => resolve(total))
				req.on('error', reject)
				req.end()
			}),
			cleanup: () => { for (const s of sessions.values()) s.destroy() },
		}
	}
	if (name === 'undici') {
		const { Agent, request } = require('undici')
		const agent = new Agent({ connect: { rejectUnauthorized: false }, allowH2: true })
		return {
			fn: async (url) => {
				const { body } = await request(url, { dispatcher: agent })
				let total = 0
				for await (const c of body) total += c.length
				return total
			},
			cleanup: () => agent.close(),
		}
	}
	if (name === 'got') {
		// got 14 is ESM-only; load via dynamic import from CJS.
		const { got } = await import('got')
		const client = got.extend({ https: { rejectUnauthorized: false }, http2: true })
		return {
			fn: async (url) => {
				const r = await client(url, { responseType: 'buffer' })
				return r.body.length
			},
			cleanup: () => {},
		}
	}
	if (name === 'axios') {
		const axios = require('axios')
		const https = require('node:https')
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		const inst = axios.create({ httpsAgent: agent, responseType: 'arraybuffer', validateStatus: () => true })
		return {
			fn: async (url) => {
				const r = await inst.get(url)
				return Buffer.from(r.data).length
			},
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'node-fetch') {
		// node-fetch v3 is ESM-only.
		const { default: fetch } = await import('node-fetch')
		const https = require('node:https')
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		return {
			fn: async (url) => {
				const r = await fetch(url, { agent })
				const b = await r.arrayBuffer()
				return b.byteLength
			},
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'fetch-native') {
		// Node's built-in undici-backed fetch. For self-signed local certs we need to install
		// a permissive dispatcher — native fetch ignores NODE_TLS_REJECT_UNAUTHORIZED.
		const { Agent, setGlobalDispatcher } = require('undici')
		setGlobalDispatcher(new Agent({ connect: { rejectUnauthorized: false } }))
		return {
			fn: async (url) => {
				const r = await fetch(url)
				const b = await r.arrayBuffer()
				return b.byteLength
			},
			cleanup: () => {},
		}
	}
	throw new Error(`unknown client: ${name}`)
}

function percentile(arr, p) {
	const a = arr.slice().sort((x, y) => x - y)
	const idx = Math.floor((p / 100) * (a.length - 1))
	return a[idx]
}

async function run() {
	const url = TARGET === 'local'
		? `https://127.0.0.1:${PORT}/`
		: (TARGET.includes('/') ? `https://${TARGET}` : `https://${TARGET}/`)

	const ad = await makeAdapter(CLIENT)
	const rssBefore = process.memoryUsage().rss

	// COLD: first request through this client. Includes TLS handshake.
	const tCold = process.hrtime.bigint()
	try { await ad.fn(url) } catch (e) {
		console.error(`cold failed: ${e.code || ''} ${e.message}`)
		process.exit(2)
	}
	const coldMs = Number(process.hrtime.bigint() - tCold) / 1e6

	// WARM-SERIAL
	const warmTimes = []
	for (let i = 0; i < WARM_REPS; i++) {
		const t = process.hrtime.bigint()
		await ad.fn(url)
		warmTimes.push(Number(process.hrtime.bigint() - t) / 1e6)
	}

	// CONCURRENT
	const tConc = process.hrtime.bigint()
	await Promise.all(Array.from({ length: CONCURRENT }, () => ad.fn(url)))
	const concWallMs = Number(process.hrtime.bigint() - tConc) / 1e6

	const rssAfter = process.memoryUsage().rss
	ad.cleanup()

	const result = {
		coldMs,
		warmP50: percentile(warmTimes, 50),
		warmP99: percentile(warmTimes, 99),
		concWallMs,
		concRps: (CONCURRENT * 1000) / concWallMs,
		rssDeltaMB: (rssAfter - rssBefore) / 1024 / 1024,
	}
	console.log(JSON.stringify(result))
	process.exit(0)
}

run()
