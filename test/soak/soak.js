// Soak test: send many requests against a local h2 server, watch for memory growth
// and handle leaks. Not part of the unit test suite — invoke via `npm run test:soak`.

const http2 = require('node:http2')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execSync } = require('node:child_process')

const TOTAL_REQUESTS = parseInt(process.env.SOAK_REQUESTS || '2000', 10)
const CONCURRENCY    = parseInt(process.env.SOAK_CONCURRENCY || '50', 10)
const SAMPLE_EVERY   = 200
const HEAP_GROWTH_BUDGET_MB = parseInt(process.env.SOAK_HEAP_BUDGET_MB || '40', 10)

function genCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'soak-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

const { key, cert } = genCert()
const server = http2.createSecureServer({ key, cert })
server.on('stream', (stream) => {
	stream.respond({ ':status': 200, 'content-type': 'application/json' })
	stream.end(JSON.stringify({ ts: Date.now(), payload: 'x'.repeat(512) }))
})

server.listen(0, '127.0.0.1', async () => {
	const port = server.address().port
	const request = require('../../')

	const start = Date.now()
	const samples = []
	let baseline = null
	let inFlight = 0
	let done = 0

	function snapshot(stage) {
		const m = process.memoryUsage()
		const h = process._getActiveHandles?.()?.length ?? -1
		const r = process._getActiveRequests?.()?.length ?? -1
		const row = {
			stage, done,
			heapUsedMB: +(m.heapUsed / 1024 / 1024).toFixed(2),
			rssMB:      +(m.rss / 1024 / 1024).toFixed(2),
			external:   +(m.external / 1024 / 1024).toFixed(2),
			handles:    h,
			requests:   r,
		}
		samples.push(row)
		console.log(JSON.stringify(row))
	}

	function pump() {
		while (inFlight < CONCURRENCY && done + inFlight < TOTAL_REQUESTS) {
			inFlight++
			request({
				url: `https://127.0.0.1:${port}/`,
				verifyTLS: false,
				json: true,
			}).then(
				() => {
					inFlight--
					done++
					if (done % SAMPLE_EVERY === 0) snapshot('checkpoint')
					if (done < TOTAL_REQUESTS) pump()
					else finish()
				},
				(e) => {
					console.error('FAIL', done, e.code, e.message)
					process.exit(2)
				},
			)
		}
	}

	function finish() {
		if (inFlight > 0) return
		// Force-close pooled connections so the post-load snapshot is honest.
		request.pool.closeAll()
		// Give Node a tick to drain.
		setImmediate(() => {
			if (global.gc) global.gc()
			snapshot('post-close')

			const elapsedSec = ((Date.now() - start) / 1000).toFixed(2)
			console.log(`\nSummary: ${TOTAL_REQUESTS} reqs in ${elapsedSec}s (${(TOTAL_REQUESTS / elapsedSec).toFixed(0)} rps)`)

			// Heap growth check. We compare the LAST checkpoint to the FIRST checkpoint (not the
			// process baseline — there's always startup allocation). A leak shows up as monotonic
			// growth that doesn't reset after pool.closeAll().
			const firstCheckpoint = samples.find((s) => s.stage === 'checkpoint') || samples[0]
			const postClose       = samples.find((s) => s.stage === 'post-close')
			const heapGrowth = postClose.heapUsedMB - firstCheckpoint.heapUsedMB
			const rssGrowth  = postClose.rssMB - firstCheckpoint.rssMB
			console.log(`Heap growth: ${heapGrowth.toFixed(2)} MB; RSS growth: ${rssGrowth.toFixed(2)} MB`)
			console.log(`Final handles: ${postClose.handles}; requests: ${postClose.requests}`)

			let failed = false
			if (heapGrowth > HEAP_GROWTH_BUDGET_MB) {
				console.error(`FAIL heap growth ${heapGrowth.toFixed(2)} MB exceeds budget ${HEAP_GROWTH_BUDGET_MB} MB`)
				failed = true
			}
			// Handle count should drop to roughly the server-listen handle + stdio + (a few internal Node handles).
			// We're permissive: budget 20 active handles. A true leak shows hundreds.
			if (postClose.handles > 30) {
				console.error(`FAIL ${postClose.handles} active handles after pool.closeAll() — possible socket leak`)
				failed = true
			}
			server.close(() => process.exit(failed ? 1 : 0))
		})
	}

	snapshot('start')
	baseline = samples[0]
	pump()
})
