// Benchmark hellojs against the major Node.js HTTP clients.
//
// We run TWO scenarios per client:
//   1. LOCAL h2 server — deterministic, measures the client's own overhead
//   2. Real internet target (tls.peet.ws) — representative, measures end-to-end
//
// For each scenario, we measure:
//   - Cold connect: time to first byte on the FIRST request (includes TLS handshake)
//   - Warm-serial:  30 sequential reqs on a reused connection (median + p99)
//   - Concurrent:   wall time for 50 parallel reqs
//   - RSS delta:    memory growth during the run
//
// Each client is run in its own subprocess so module-level caches don't bleed across
// runs. Numbers below are MS unless noted otherwise.

const { spawn } = require('node:child_process')
const path = require('node:path')
const http2 = require('node:http2')
const fs = require('node:fs')
const os = require('node:os')
const { execSync } = require('node:child_process')

const WARM_REPS = parseInt(process.env.WARM_REPS || '30', 10)
const CONCURRENT = parseInt(process.env.CONCURRENT || '50', 10)
const REMOTE_TARGET = process.env.REMOTE_TARGET || 'tls.peet.ws/api/all'
const REMOTE_WARM_REPS = parseInt(process.env.REMOTE_WARM_REPS || '10', 10)
const REMOTE_CONCURRENT = parseInt(process.env.REMOTE_CONCURRENT || '8', 10)

function genCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

// Tiny worker script that runs ONE client against ONE target and prints JSON.
const WORKER = path.join(__dirname, 'bench-worker.js')

function runWorker(client, target, port, opts = {}) {
	const perRunTimeoutMs = opts.timeoutMs || 90_000
	return new Promise((resolve) => {
		const env = {
			...process.env,
			BENCH_CLIENT: client, BENCH_TARGET: target, BENCH_PORT: String(port || ''),
			BENCH_WARM_REPS: String(opts.warmReps || WARM_REPS),
			BENCH_CONCURRENT: String(opts.concurrent || CONCURRENT),
		}
		// Only disable TLS verification for the LOCAL self-signed scenario. Remote targets
		// have valid certs and the env var emits a stderr warning that pollutes our error
		// capture.
		if (target === 'local') env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
		const child = spawn(process.execPath, [WORKER], { env, stdio: ['ignore', 'pipe', 'pipe'] })
		let out = '', err = ''
		const timer = setTimeout(() => { try { child.kill('SIGKILL') } catch (_) {} }, perRunTimeoutMs)
		child.stdout.on('data', (d) => out += d.toString())
		child.stderr.on('data', (d) => err += d.toString())
		child.on('exit', (code, signal) => {
			clearTimeout(timer)
			if (signal === 'SIGKILL') {
				resolve({ client, error: `timeout >${perRunTimeoutMs / 1000}s` })
			} else if (code !== 0) {
				// Skip Node warnings/banners and blank lines so the captured error is the
				// actual failure cause, not a deprecation notice.
				const lines = err.trim().split('\n').filter((l) => {
					const t = l.trim()
					if (!t) return false
					if (/^\(node:\d+\)/.test(t)) return false           // (node:1234) Warning: ...
					if (/^Node\.js v/i.test(t)) return false           // version footer
					if (/^Use `node --trace-/i.test(t)) return false   // trace hints
					return true
				})
				resolve({ client, error: (lines[0] || `exit ${code}`).slice(0, 80) })
			} else {
				try { resolve({ client, ...JSON.parse(out.trim()) }) }
				catch { resolve({ client, error: 'parse failed: ' + out.slice(0, 100) }) }
			}
		})
		process.stderr.write(`  · ${client} → ${target}${port ? ':' + port : ''} (warm=${opts.warmReps || WARM_REPS}, conc=${opts.concurrent || CONCURRENT})\n`)
	})
}

function pad(s, n) { return String(s).padEnd(n) }
function fmt(n) { return n == null ? '-' : (typeof n === 'number' ? n.toFixed(1) : String(n)) }

function printTable(rows, scenario) {
	console.log(`\n--- ${scenario} ---`)
	console.log(`${pad('client', 14)} ${pad('cold', 10)} ${pad('p50/warm', 10)} ${pad('p99/warm', 10)} ${pad('conc50', 10)} ${pad('rss Δ', 10)}`)
	console.log('-'.repeat(70))
	for (const r of rows) {
		if (r.error) {
			console.log(`${pad(r.client, 14)} ERROR: ${r.error.slice(0, 50)}`)
		} else {
			console.log(`${pad(r.client, 14)} ${pad(fmt(r.coldMs), 10)} ${pad(fmt(r.warmP50), 10)} ${pad(fmt(r.warmP99), 10)} ${pad(fmt(r.concWallMs), 10)} ${pad(fmt(r.rssDeltaMB) + ' MB', 10)}`)
		}
	}
}

;(async () => {
	const clients = ['hellojs', 'node-https', 'node-http2', 'undici', 'got', 'axios', 'node-fetch', 'fetch-native']

	console.log('# Node HTTP-client benchmark\n')
	console.log(`Node ${process.version}  WARM_REPS=${WARM_REPS}  CONCURRENT=${CONCURRENT}\n`)

	// ---- Scenario 1: LOCAL h2 server (cert validation off) ----
	console.log('## Scenario 1: local h2 server (loopback, fixed-size response)')
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => {
		s.respond({ ':status': 200, 'content-type': 'application/octet-stream' })
		s.end(Buffer.alloc(1024, 0x41))
	})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	const localResults = []
	for (const c of clients) {
		const r = await runWorker(c, 'local', port)
		localResults.push(r)
	}
	printTable(localResults, 'local h2 server (127.0.0.1, 1KB body)')
	server.close()

	// ---- Scenario 2: real internet target ----
	// Use a smaller load to avoid rate-limiting; rest a beat between clients so the
	// target's per-IP rate-limit cools off.
	console.log(`\n\n## Scenario 2: ${REMOTE_TARGET} (real internet, warm=${REMOTE_WARM_REPS} conc=${REMOTE_CONCURRENT})`)
	const [remoteHost, ...pathParts] = REMOTE_TARGET.split('/')
	const remoteResults = []
	for (const c of clients) {
		const r = await runWorker(c, REMOTE_TARGET, 443, { warmReps: REMOTE_WARM_REPS, concurrent: REMOTE_CONCURRENT })
		remoteResults.push(r)
		// Cooldown between clients so peet.ws doesn't blacklist us.
		await new Promise((r) => setTimeout(r, 3000))
	}
	printTable(remoteResults, `${REMOTE_TARGET} (real internet)`)

	// ---- Notes ----
	console.log(`\nNotes:`)
	console.log(`  cold      = time to first byte on the FIRST request, including TLS handshake`)
	console.log(`  p50/warm  = median of ${WARM_REPS} sequential reused-connection requests`)
	console.log(`  p99/warm  = 99th percentile of those ${WARM_REPS} reqs`)
	console.log(`  conc50    = wall time for ${CONCURRENT} parallel requests (h2 multiplexes; h1 serializes per conn)`)
	console.log(`  rss Δ     = process.memoryUsage().rss before vs after the run`)
	console.log(`\n  hellojs is the ONLY client whose JA4 matches a real Chrome 147 browser.`)

	process.exit(0)
})()
