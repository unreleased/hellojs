// Public request.js-shape API.
//
//   const request = require('hellojs')
//   request({ url, method, headers, body, json, qs, jar, gzip, followRedirect, timeout, proxy, forever }, (err, res, body) => {})
//   request({...}).then(res => {})            // promise form
//   request({...}, cb).pipe(stream)           // streaming
//   request.get/post/put/del/patch/head/options
//   request.defaults(opts)
//   request.jar()
//
// Notes:
// - Driven by lib/pool.js and lib/tls/tls.js for TLS+HTTP/2.
// - HTTP/1.1 fallback is hand-rolled (chunked, content-length).
// - Auto-decompresses gzip / br / deflate / zstd response bodies when {gzip:true} or content-encoding seen.

const { URL } = require('url')
const querystring = require('querystring')
const zlib = require('zlib')
const { Readable, PassThrough } = require('stream')
const { defaultPool, recordAltSvc, lookupAltSvc } = require('./pool')
const { buildH2Headers, buildH1Headers } = require('./headers')
const profileRegistry = require('./profiles')
const { observability, nextRequestId } = require('./observability')

const { HellojsError, wrap: wrapError } = require('./errors')

// RFC 6265-compliant cookie jar lives in lib/cookies.js.
const { Jar } = require('./cookies')

function decompressIfNeeded(buf, encoding) {
	const e = (encoding || '').toLowerCase()
	if (!e || e === 'identity') return buf
	if (e.includes('gzip')) return zlib.gunzipSync(buf)
	if (e.includes('br')) return zlib.brotliDecompressSync(buf)
	if (e.includes('deflate')) {
		try { return zlib.inflateSync(buf) } catch { return zlib.inflateRawSync(buf) }
	}
	if (e.includes('zstd')) {
		// Node 23.8+ has zlib.zstdDecompressSync. Fall back to pure-JS fzstd for older Nodes.
		if (typeof zlib.zstdDecompressSync === 'function') return zlib.zstdDecompressSync(buf)
		const fzstd = require('fzstd')
		return Buffer.from(fzstd.decompress(buf))
	}
	return buf
}

// Streaming counterpart: return a Transform that the response body can be piped through.
// `null` means "no decoding needed — caller can read the body as-is."
function decompressStreamForEncoding(encoding) {
	const e = (encoding || '').toLowerCase()
	if (!e || e === 'identity') return null
	if (e.includes('gzip')) return zlib.createGunzip()
	if (e.includes('br'))   return zlib.createBrotliDecompress()
	if (e.includes('deflate')) {
		// Some servers send raw deflate; createInflate auto-detects, but to match the sync path
		// we use createInflate and rely on Node's auto-fallback to raw.
		return zlib.createInflate()
	}
	if (e.includes('zstd') && typeof zlib.createZstdDecompress === 'function') {
		return zlib.createZstdDecompress()
	}
	return null  // zstd on Node < 23.8 is buffered-only via fzstd
}

function buildUrl(opts) {
	let url = opts.url || opts.uri
	if (!url) throw new HellojsError('missing url', 'EBADOPTS')
	if (opts.qs) {
		const qs = querystring.stringify(opts.qs)
		url += (url.includes('?') ? '&' : '?') + qs
	}
	return new URL(url)
}

function prepareBody(opts) {
	if (opts.body !== undefined) {
		// Streaming bodies: pass the Readable through; we'll send it as h2 DATA frames or h1 chunked.
		if (opts.body && typeof opts.body === 'object' && typeof opts.body.pipe === 'function') return opts.body
		if (typeof opts.body === 'string' || Buffer.isBuffer(opts.body)) return Buffer.from(opts.body)
		if (opts.json && typeof opts.body === 'object') return Buffer.from(JSON.stringify(opts.body))
		if (typeof opts.body === 'object') return Buffer.from(JSON.stringify(opts.body))
	}
	if (opts.json && typeof opts.json !== 'boolean') {
		return Buffer.from(JSON.stringify(opts.json))
	}
	if (opts.form) {
		return Buffer.from(querystring.stringify(opts.form))
	}
	return null
}

function shouldDoJsonContentType(opts, body) {
	if (!body) return false
	if (opts.json && (typeof opts.json === 'object' || (opts.json === true && typeof opts.body === 'object'))) return true
	return false
}

async function performRequest(opts) {
	const url = buildUrl(opts)
	const method = (opts.method || 'GET').toUpperCase()
	const host = url.hostname
	const port = url.port ? parseInt(url.port, 10) : 443
	const _reqId = opts._reqId || (opts._reqId = nextRequestId())
	const _t0 = Date.now()
	observability.safeEmit('request:start', { id: _reqId, method, url: url.toString(), headers: opts.headers })
	const profile = opts.profile || 'chrome147-mac'
	// Resolve to the actual profile object for header / pseudo-header / priority building.
	// Tolerate unknown names (caller may have a custom profile registered elsewhere) — the TLS
	// layer will throw a clearer error if the name truly isn't valid.
	let profileObj = null
	try { profileObj = profileRegistry.get(profile) } catch (_) { profileObj = null }

	// Decide transport: explicit opts.h3 wins; otherwise check Alt-Svc cache (auto-upgrade like Chrome).
	let transport = 'tcp'
	let actualPort = port
	if (opts.h3 === true) {
		transport = 'quic'
	} else if (opts.h3 !== false) {
		const alt = lookupAltSvc(host)
		if (alt) {
			transport = 'quic'
			actualPort = alt.port
		}
	}

	// 0-RTT early-data hook: caller supplies raw bytes via opts.earlyData. The bytes are
	// sent under the 0-RTT keys in the same flight as ClientHello, so the server can start
	// processing before the handshake finishes. ONLY safe for replay-tolerant operations
	// (RFC 8470 — idempotent HTTP methods, etc.). Currently TCP transport only.
	const earlyData = (opts.earlyData && transport === 'tcp') ? Buffer.from(opts.earlyData) : null

	let conn
	try {
		conn = await defaultPool.acquire({
			host, port: actualPort, profile, proxy: opts.proxy,
			forceFresh: opts.forever === false,
			transport,
			earlyData,
			verifyTLS: opts.verifyTLS !== false,
			timeouts: opts.timeouts,
		})
	} catch (e) {
		// If h3 was attempted via Alt-Svc and failed, fall back to TCP.
		if (transport === 'quic' && opts.h3 !== true) {
			conn = await defaultPool.acquire({
				host, port, profile, proxy: opts.proxy,
				forceFresh: opts.forever === false,
				transport: 'tcp',
				earlyData,
				verifyTLS: opts.verifyTLS !== false,
				timeouts: opts.timeouts,
			})
		} else {
			throw e
		}
	}

	// Build headers
	const userHeaders = { ...(opts.headers || {}) }
	if (opts.jar) {
		const cookie = opts.jar.getCookieString(url.toString())
		if (cookie) userHeaders['cookie'] = cookie
	}
	const body = prepareBody(opts)
	if (body && !userHeaders['content-type']) {
		if (shouldDoJsonContentType(opts, body)) userHeaders['content-type'] = 'application/json'
		else if (opts.form) userHeaders['content-type'] = 'application/x-www-form-urlencoded'
	}
	const isStream = body && typeof body === 'object' && typeof body.pipe === 'function'
	if (body && !isStream && !userHeaders['content-length']) userHeaders['content-length'] = String(body.length)
	if (isStream && !userHeaders['content-length'] && !userHeaders['transfer-encoding']) {
		// h2 doesn't need either header (frame length is implicit); for h1 we'll use chunked.
		if (conn.alpn === 'http/1.1') userHeaders['transfer-encoding'] = 'chunked'
	}

	conn.activeRequests++
	try {
		if (conn.alpn === 'h3') return await performH3(conn, { method, url, host, body, userHeaders, opts, profileObj })
		if (conn.alpn === 'h2') return await performH2(conn, { method, url, host, body, userHeaders, opts, profileObj })
		conn.h1InFlight = true
		try {
			return await performH1(conn, { method, url, host, body, userHeaders, opts, profileObj })
		} finally {
			conn.h1InFlight = false
		}
	} finally {
		conn.activeRequests--
	}
}

async function performH3(conn, { method, url, host, body, userHeaders, opts, profileObj: _profileObj }) {
	const headers = { ...userHeaders }
	const t0 = Date.now()
	const res = await conn.h3Client.request({
		method,
		path: url.pathname + url.search,
		host,
		headers,
		body,
	})
	conn.markUsed()
	conn.scheduleIdleClose(defaultPool.idleTimeoutMs)
	let raw = res.body
	try { raw = decompressIfNeeded(raw, res.headers['content-encoding']) } catch (e) { throw e }
	if (opts.jar && res.headers['set-cookie']) opts.jar.setCookie(res.headers['set-cookie'], url.toString())
	let bodyOut = raw
	if (opts.json && raw.length) { try { bodyOut = JSON.parse(raw.toString('utf8')) } catch {} }
	else if (raw.length && res.headers['content-type']?.includes('text')) bodyOut = raw.toString('utf8')
	return new Promise((resolve, reject) => handleResponse({ status: res.status, headers: res.headers, body: bodyOut, raw, opts, resolve, reject }))
}

function performH2(conn, { method, url, host, body, userHeaders, opts, profileObj }) {
	return new Promise((resolve, reject) => {
		const headers = buildH2Headers({ method, host, path: url.pathname + url.search, userHeaders, profile: profileObj })
		const isStreamingBody = body && typeof body === 'object' && typeof body.pipe === 'function'
		const reqId = opts._reqId
		const reqT0 = Date.now()
		// PRIORITY-on-HEADERS values default to the profile when present; otherwise H2Session
		// falls back to Chrome's exclusive/weight=256. Passing `null` here lets H2Session pick.
		const reqOpts = { endStream: !body }
		const req = conn.h2Session.request(headers, reqOpts)
		observability.safeEmit('request:headersSent', { id: reqId, method, path: url.pathname + url.search })
		const respMs = opts.timeouts?.response ?? opts.timeout
		const timer = respMs ? setTimeout(() => {
			req.close(0x8 /*CANCEL*/)
			const e = new HellojsError(`request timed out after ${respMs}ms`, 'ETIMEDOUT')
			observability.safeEmit('request:error', { id: reqId, code: 'ETIMEDOUT', message: e.message, durationMs: Date.now() - reqT0 })
			reject(e)
		}, respMs) : null
		let firstByteEmitted = false

		// Streaming response path: when opts.stream is true, resolve as soon as headers arrive
		// with the body exposed as a Readable that callers can `.pipe()` into a Writable.
		if (opts.stream) {
			let settled = false
			req.on('response', (h) => {
				if (settled) return
				settled = true
				if (timer) clearTimeout(timer)
				const status = parseInt(h?.[':status'] ?? 0, 10)
				if (h?.['alt-svc']) recordAltSvc(host, h['alt-svc'])
				if (opts.jar && h?.['set-cookie']) opts.jar.setCookie(h['set-cookie'], url.toString())

				const pt = new PassThrough()
				const decoder = decompressStreamForEncoding(h?.['content-encoding'])
				const userStream = decoder ? pt.pipe(decoder) : pt

				req.on('data', (c) => pt.write(c))
				req.on('end', () => {
					pt.end()
					conn.markUsed()
					conn.scheduleIdleClose(opts.timeouts?.idle ?? defaultPool.idleTimeoutMs)
				})
				req.on('error', (e) => pt.destroy(new HellojsError(e.message, 'EH2STREAM', e)))

				const res = { statusCode: status, status, headers: h, body: userStream, rawBody: userStream }
				if (opts.simple !== false && status >= 400) {
					const err = new HellojsError(`HTTP ${status}`, 'EHTTP')
					err.response = res
					req.close(0x8); pt.destroy(err)
					return reject(err)
				}
				resolve(opts.resolveWithFullResponse ? res : userStream)
			})
			req.on('error', (e) => { if (settled) return; settled = true; if (timer) clearTimeout(timer); reject(new HellojsError(e.message, 'EH2STREAM', e)) })
			if (isStreamingBody) {
				body.on('data', (c) => req.write(Buffer.isBuffer(c) ? c : Buffer.from(c)))
				body.on('end', () => req.end())
				body.on('error', (e) => { try { req.close(0x8) } catch (_) {}; reject(new HellojsError(e.message, 'EBODYSTREAM', e)) })
			} else if (body) req.end(body)
			else req.end()
			return
		}

		const chunks = []
		let resHeaders
		let totalBytes = 0
		req.on('response', (h) => { resHeaders = h })
		req.on('data', (c) => {
			chunks.push(c); totalBytes += c.length
			if (!firstByteEmitted) {
				firstByteEmitted = true
				observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 })
			}
		})
		req.on('end', () => {
			if (timer) clearTimeout(timer)
			conn.markUsed()
			conn.scheduleIdleClose(opts.timeouts?.idle ?? defaultPool.idleTimeoutMs)
			let raw = Buffer.concat(chunks)
			try { raw = decompressIfNeeded(raw, resHeaders?.['content-encoding']) } catch (e) { return reject(new HellojsError(e.message, 'EDECOMPRESS', e)) }
			const status = parseInt(resHeaders?.[':status'] ?? 0, 10)
			observability.safeEmit('request:end', { id: reqId, status, headers: resHeaders, totalBytes, durationMs: Date.now() - reqT0 })
			if (resHeaders?.['alt-svc']) recordAltSvc(host, resHeaders['alt-svc'])
			if (opts.jar && resHeaders?.['set-cookie']) opts.jar.setCookie(resHeaders['set-cookie'], url.toString())
			let bodyOut = raw
			if (opts.json && raw.length) {
				try { bodyOut = JSON.parse(raw.toString('utf8')) } catch { /* leave as buffer */ }
			} else if (raw.length && resHeaders?.['content-type']?.includes('utf-8')) {
				bodyOut = raw.toString('utf8')
			}
			handleResponse({ status, headers: resHeaders, body: bodyOut, raw, opts, resolve, reject })
		})
		req.on('error', (e) => { if (timer) clearTimeout(timer); reject(new HellojsError(e.message, 'EH2STREAM', e)) })
		if (isStreamingBody) {
			body.on('data', (c) => req.write(Buffer.isBuffer(c) ? c : Buffer.from(c)))
			body.on('end', () => req.end())
			body.on('error', (e) => { try { req.close(0x8) } catch (_) {}; reject(new HellojsError(e.message, 'EBODYSTREAM', e)) })
		} else if (body) req.end(body)
		else req.end()
	})
}

async function performH1(conn, { method, url, host, body, userHeaders, opts, profileObj }) {
	// Hand-rolled HTTP/1.1 over the TLSTransport.
	const transport = conn.h2Transport  // misnomer: this is the raw TLS Duplex
	const requestLine = `${method} ${url.pathname + url.search} HTTP/1.1\r\n`
	const headerBlock = buildH1Headers({ host, userHeaders, profile: profileObj })
	const head = Buffer.from(requestLine + headerBlock + '\r\n\r\n', 'utf8')
	transport.write(head)
	if (body) transport.write(body)

	const responseChunks = []
	return new Promise((resolve, reject) => {
		const respMs = opts.timeouts?.response ?? opts.timeout
		const timer = respMs ? setTimeout(() => reject(new HellojsError(`request timed out after ${respMs}ms`, 'ETIMEDOUT')) , respMs) : null
		const onData = (c) => responseChunks.push(c)
		const onEnd = () => {
			transport.removeListener('data', onData)
			if (timer) clearTimeout(timer)
			const buf = Buffer.concat(responseChunks)
			const headerEnd = buf.indexOf(Buffer.from('\r\n\r\n'))
			if (headerEnd < 0) return reject(new HellojsError('incomplete h1 response', 'EBADRESP'))
			const headerStr = buf.slice(0, headerEnd).toString('latin1')
			const lines = headerStr.split('\r\n')
			const statusLine = lines.shift()
			const m = statusLine.match(/^HTTP\/1\.\d (\d{3}) (.*)$/)
			const status = m ? parseInt(m[1], 10) : 0
			const headers = {}
			for (const ln of lines) {
				const idx = ln.indexOf(':')
				if (idx < 0) continue
				const k = ln.slice(0, idx).trim().toLowerCase()
				const v = ln.slice(idx + 1).trim()
				if (headers[k]) headers[k] = [].concat(headers[k], v); else headers[k] = v
			}
			let entity = buf.subarray(headerEnd + 4)
			if (/\bchunked\b/i.test(headers['transfer-encoding'] || '')) {
				entity = dechunk(entity)
			} else if (headers['content-length']) {
				entity = entity.subarray(0, parseInt(headers['content-length'], 10))
			}
			let raw = entity
			try { raw = decompressIfNeeded(raw, headers['content-encoding']) } catch (e) { return reject(e) }
			if (opts.jar && headers['set-cookie']) opts.jar.setCookie(headers['set-cookie'], url.toString())
			let bodyOut = raw
			if (opts.json && raw.length) { try { bodyOut = JSON.parse(raw.toString('utf8')) } catch {} }
			else if (raw.length) bodyOut = raw.toString('utf8')
			handleResponse({ status, headers, body: bodyOut, raw, opts, resolve, reject })
		}
		transport.on('data', onData)
		transport.once('end', onEnd)
	})
}

function dechunk(buf) {
	const out = []
	let off = 0
	while (off < buf.length) {
		const nl = buf.indexOf(Buffer.from('\r\n'), off)
		if (nl < 0) break
		const sz = parseInt(buf.slice(off, nl).toString('ascii').trim(), 16)
		if (Number.isNaN(sz)) break
		const start = nl + 2, end = start + sz
		out.push(buf.slice(start, end))
		off = end + 2
		if (sz === 0) break
	}
	return Buffer.concat(out)
}

function handleResponse({ status, headers, body, raw, opts, resolve, reject }) {
	const res = { statusCode: status, status, headers, body, rawBody: raw }
	if (opts.simple !== false && status >= 400) {
		const err = new HellojsError(`HTTP ${status}`, 'EHTTP')
		err.response = res
		return reject(err)
	}
	if (opts.followRedirect !== false && status >= 300 && status < 400 && headers.location && (opts.maxRedirects ?? 10) > 0) {
		const newOpts = { ...opts, url: new URL(headers.location, opts.url || opts.uri).toString(), maxRedirects: (opts.maxRedirects ?? 10) - 1 }
		if (status === 303) newOpts.method = 'GET'
		return resolve(performRequest(newOpts))
	}
	if (opts.resolveWithFullResponse) return resolve(res)
	resolve(opts.json ? body : (typeof body === 'string' ? body : raw))
}

// Public API ------------------------------------------------------------

async function performWithRetry(opts) {
	const policy = opts.retry || {}
	const limit = policy.limit ?? 0
	const methods = policy.methods ?? ['GET', 'HEAD', 'OPTIONS']
	const statusCodes = policy.statusCodes ?? [408, 429, 500, 502, 503, 504]
	const baseDelay = policy.baseDelayMs ?? 200
	const upper = (opts.method || 'GET').toUpperCase()
	const retriable = methods.includes(upper)
	let lastErr
	for (let attempt = 0; attempt <= limit; attempt++) {
		try {
			return await performRequest(opts)
		} catch (e) {
			// Normalize: every error leaving this function is a HellojsError with a stable .code.
			lastErr = wrapError(e)
			const status = lastErr?.response?.status
			const transient = (status && statusCodes.includes(status)) ||
				['ETIMEDOUT', 'ECONNRESET', 'EH2STREAM', 'EH3STREAM'].includes(lastErr.code)
			if (!retriable || !transient || attempt === limit) throw lastErr
			const delay = baseDelay * Math.pow(2, attempt)
			await new Promise((r) => setTimeout(r, delay))
		}
	}
	throw lastErr
}

function request(opts, cb) {
	if (typeof opts === 'string') opts = { url: opts }
	const p = performWithRetry(opts)
	if (cb) {
		p.then(r => cb(null, opts.resolveWithFullResponse ? r : r, opts.resolveWithFullResponse ? r.body : r),
			e => cb(e, e?.response, e?.response?.body))
	}
	return p
}

function method(m) {
	return (urlOrOpts, cb) => {
		const opts = typeof urlOrOpts === 'string' ? { url: urlOrOpts } : { ...urlOrOpts }
		opts.method = m
		return request(opts, cb)
	}
}

request.get     = method('GET')
request.post    = method('POST')
request.put     = method('PUT')
request.del     = method('DELETE')
request.delete  = method('DELETE')
request.patch   = method('PATCH')
request.head    = method('HEAD')
request.options = method('OPTIONS')

// Deep-merge defaults + per-call opts, with `headers` lowercased and merged (later wins).
function mergeOpts(base, over) {
	const out = { ...base, ...over }
	const lowerCaseHeaders = (h) => {
		if (!h) return {}
		const o = {}
		for (const [k, v] of Object.entries(h)) o[k.toLowerCase()] = v
		return o
	}
	out.headers = { ...lowerCaseHeaders(base.headers), ...lowerCaseHeaders(over.headers) }
	return out
}

request.defaults = (defaults = {}) => {
	const wrapped = (urlOrOpts, cb) => {
		const opts = typeof urlOrOpts === 'string' ? { url: urlOrOpts } : urlOrOpts
		return request(mergeOpts(defaults, opts), cb)
	}
	const shortcut = (m) => (urlOrOpts, cb) => {
		const opts = typeof urlOrOpts === 'string' ? { url: urlOrOpts } : { ...urlOrOpts }
		opts.method = m
		return wrapped(opts, cb)
	}
	wrapped.get     = shortcut('GET')
	wrapped.post    = shortcut('POST')
	wrapped.put     = shortcut('PUT')
	wrapped.del     = shortcut('DELETE')
	wrapped.delete  = shortcut('DELETE')
	wrapped.patch   = shortcut('PATCH')
	wrapped.head    = shortcut('HEAD')
	wrapped.options = shortcut('OPTIONS')
	wrapped.defaults = (more) => request.defaults(mergeOpts(defaults, more || {}))
	wrapped.jar = request.jar
	return wrapped
}

request.jar = () => new Jar()
request.HellojsError = HellojsError
request.pool = defaultPool

module.exports = request
