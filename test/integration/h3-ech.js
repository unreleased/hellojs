// Test explicit HTTP/3 + ECH against a public origin that publishes HTTPS/SVCB ECH metadata.

const request = require('../../')

;(async () => {
	let pass = 0, fail = 0
	const log = (label, ok, detail) => {
		if (ok) { pass++; console.log(`\x1b[32mPASS\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
		else { fail++; console.log(`\x1b[31mFAIL\x1b[0m ${label}${detail ? ' — ' + detail : ''}`) }
	}

	const HOST = process.env.H3_ECH_HOST || 'cloudflare-ech.com'
	const PATH = process.env.H3_ECH_PATH || '/cdn-cgi/trace'
	const URL = `https://${HOST}${PATH}`

	let firstConn = null
	let firstNextStreamId = -1
	try {
		const r = await request({ url: URL, h3: true, ech: true, resolveWithFullResponse: true, simple: false })
		firstConn = [...request.pool.connections.values()].find((conn) => conn.alpn === 'h3' && conn.quicConn?.echOffered?.accepted === true) || null
		firstNextStreamId = firstConn?.quicConn?.nextClientBidiStreamId ?? -1
		log('explicit h3+ech request', r.status === 200 && r.rawBody.length > 0 && !!firstConn, `status=${r.status} bytes=${r.rawBody.length} echAccepted=${!!firstConn}`)
	} catch (e) {
		log('explicit h3+ech request', false, e.message)
	}

	try {
		const r = await request({ url: URL, h3: true, ech: true, resolveWithFullResponse: true, simple: false })
		const pooledConn = [...request.pool.connections.values()].find((conn) => conn === firstConn)
		const reused = !!pooledConn && pooledConn.quicConn?.echOffered?.accepted === true && pooledConn.quicConn.nextClientBidiStreamId === firstNextStreamId + 4
		log('second h3+ech request on pooled path', r.status === 200 && r.rawBody.length > 0 && reused, `status=${r.status} bytes=${r.rawBody.length} reused=${reused} streamId=${pooledConn?.quicConn?.nextClientBidiStreamId ?? -1}`)
	} catch (e) {
		log('second h3+ech request on pooled path', false, e.message)
	}

	console.log(`\n${pass}/${pass + fail} passed`)
	request.pool.closeAll()
	process.exit(fail ? 1 : 0)
})()
