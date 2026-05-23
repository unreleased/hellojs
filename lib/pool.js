// Connection pool keyed by (host, port, profile, transport).
// - Caches live TLS+H2 sessions so subsequent requests reuse the handshake.
// - h1 connections are non-multiplexable: one in-flight at a time, but kept warm via TCP keep-alive.
// - h3 (QUIC) connections multiplex like h2.
// - Per-request override via {forever: false} forces a fresh connection.

const { TLS } = require('./tls/tls')
const { QuicConnection } = require('./h3/connection')
const { H3Client } = require('./h3/h3')
const sessionCache = require('./tls/session-cache')

const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000  // 5 minutes — Chrome-ish
const DEFAULT_MAX_PER_HOST = 6                  // Chrome's per-origin TCP connection cap

// Alt-Svc cache: host → { port, ma_expiry }. Populated when h2 responses include `alt-svc: h3=":443"; ma=N`.
const altSvcCache = new Map()

class PooledConnection {
	constructor(tls, key) {
		this.tls = tls
		this.key = key
		this.alpn = null               // 'h2' / 'http/1.1' / 'h3' once handshake done
		this.h2Session = null
		this.h2Transport = null
		this.h3Client = null           // populated for h3 connections
		this.quicConn = null
		this.idleTimer = null
		this.lastUsedAt = Date.now()
		this.closed = false
		this.h1InFlight = false        // for non-multiplexed h1
		this.activeRequests = 0        // for graceful drain
	}

	markUsed() {
		this.lastUsedAt = Date.now()
		if (this.idleTimer) clearTimeout(this.idleTimer)
		this.idleTimer = null
	}

	scheduleIdleClose(ms) {
		if (this.idleTimer) clearTimeout(this.idleTimer)
		this.idleTimer = setTimeout(() => this.close('idle'), ms).unref?.()
	}

	close(reason) {
		if (this.closed) return
		this.closed = true
		try { this.quicConn?.close() } catch (_) {}
		try { this.h2Session?.close?.() } catch (_) {}
		try { this.tls?.socket?.destroy() } catch (_) {}
	}

	canIssueRequest() {
		if (this.closed) return false
		if (this.alpn === 'h3') return !!this.quicConn && !this.quicConn._closed
		if (this.alpn === 'h2') return !this.h2Session?.destroyed && !this.h2Session?.closed
		return !this.h1InFlight
	}
}

class Pool {
	constructor(opts = {}) {
		this.idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS
		this.maxPerHost = opts.maxPerHost ?? DEFAULT_MAX_PER_HOST
		this.connections = new Map()       // key -> PooledConnection
		this.pending = new Map()           // key -> Promise<PooledConnection> for in-flight handshakes
		// host:port -> { count, waiters: [] }. Cap on simultaneously-open connections for a
		// host, including the primary pooled connection. Extra forceFresh / in-use connections
		// consume additional slots until they close.
		this.hostState = new Map()
	}

	keyOf(host, port, profile, proxy, transport, opts = {}) {
		const connectHost = opts.connectHost || host
		const tlsName = opts.tlsName || host
		const echKey = opts.ech?.publicName || opts.ech?.config?.publicName || ''
		const identityTail = `|connect=${connectHost}|tls=${tlsName}|ech=${echKey}`
		return `${transport || 'tcp'}|${host}:${port}|${profile || 'default'}|${proxy || 'noproxy'}${identityTail}`
	}

	hostKey(host, port) { return `${host}:${port}` }

	async _acquireSlot(host, port) {
		const k = this.hostKey(host, port)
		let st = this.hostState.get(k)
		if (!st) { st = { count: 0, waiters: [] }; this.hostState.set(k, st) }
		if (st.count >= this.maxPerHost) {
			await new Promise((resolve) => st.waiters.push(resolve))
		}
		st.count++
	}

	_releaseSlot(host, port) {
		const k = this.hostKey(host, port)
		const st = this.hostState.get(k)
		if (!st) return
		st.count = Math.max(0, st.count - 1)
		const w = st.waiters.shift()
		if (w) w()
		else if (st.count === 0) this.hostState.delete(k)
	}

	// Slot accounting is tied to connection lifetime, not just handshake completion. Wrap
	// `close()` as soon as a PooledConnection exists so early error/eviction paths cannot leak
	// a host slot before the ready handlers finish wiring the transport.

	_wrapConnectionClose(conn, host, port) {
		if (!conn || conn._slotReleaseWrapped) return conn
		const origClose = conn.close.bind(conn)
		let released = false
		conn.close = (reason) => {
			if (!released) { released = true; this._releaseSlot(host, port) }
			return origClose(reason)
		}
		conn._slotReleaseWrapped = true
		return conn
	}

acquire({ host, port = 443, profile, proxy, forceFresh = false, cacheConnection = null, transport = 'tcp', earlyData = null, verifyTLS = true, timeouts = null, profileObj = null, connectHost = null, tlsName = null, addressHints = null, ech = null, sessionIdentity = null }) {
		if (this._draining) {
			const { HellojsError } = require('./errors')
			return Promise.reject(new HellojsError('pool is draining; no new requests accepted', 'EPROTO'))
		}
		const key = this.keyOf(host, port, profile, proxy, transport, { connectHost, tlsName, ech })
		// earlyData implies a fresh handshake: we want to attempt 0-RTT on a new connection
		// using a cached PSK, not piggyback on whatever in-flight session is already up.
		if (earlyData) forceFresh = true
		const shouldCache = cacheConnection == null ? !forceFresh : !!cacheConnection
		// Fast paths run SYNCHRONOUSLY (no awaits) so concurrent callers don't all race past
		// the pending check before anyone sets it. This is critical: an `await` here before
		// setting `pending` lets every concurrent caller fall through and start its own
		// handshake, oversaturating the per-host slot pool and burning identical sessions.
		if (!forceFresh) {
			const existing = this.connections.get(key)
			if (existing && existing.canIssueRequest()) {
				existing.markUsed()
				return Promise.resolve(existing)
			}
			if (existing) {
				this.connections.delete(key)
				existing.close('stale')
			}
			const pending = this.pending.get(key)
			if (pending) return pending
		}
		// Synchronously install the pending promise BEFORE awaiting the slot when the finished
		// connection will be inserted into the pool.
		const p = this._acquireSlot(host, port).then(async () => {
			let conn
			try {
				conn = transport === 'quic'
					? await this._createH3(host, port, profile, key, {
						connectHost,
						tlsName,
						addressHints,
						ech,
					})
					: await this._create(host, port, profile, proxy, key, {
						earlyData,
						verifyTLS,
						timeouts,
						profileObj: profileObj || profile,
						connectHost,
						tlsName,
						addressHints,
						ech,
						sessionIdentity,
					})
			} catch (e) {
				this._releaseSlot(host, port)
				throw e
			}

			// `forceFresh` may still be cacheable (ECH retry path). In that case we bypass the
			// fast-path reuse checks for the current acquire, but still publish the finished
			// connection for later requests under the same logical identity.
			if (shouldCache) {
				const existing = this.connections.get(key)
				if (!existing) {
					this.connections.set(key, conn)
				} else if (existing !== conn && (existing.closed || !existing.canIssueRequest())) {
					this.connections.delete(key)
					existing.close('replaced')
					this.connections.set(key, conn)
				}
			}
			return conn
		})
		if (shouldCache) {
			this.pending.set(key, p)
			// Use .then(_, _) instead of .finally(...) so this swallowed chain doesn't
			// become an unhandled rejection (separate from the rejection user code sees on `p`).
			p.then(
				() => { if (this.pending.get(key) === p) this.pending.delete(key) },
				() => { if (this.pending.get(key) === p) this.pending.delete(key) },
			)
		}
		return p
	}

	_createH3(host, port, profile, key, opts = {}) {
		return new Promise((resolve, reject) => {
			const qc = new QuicConnection(host, port, {
				connectHost: opts.connectHost || host,
				serverName: opts.tlsName || host,
				addressHints: opts.addressHints || null,
				ech: opts.ech || null,
			})
			const conn = this._wrapConnectionClose(new PooledConnection(null, key), host, port)
			conn.quicConn = qc
			let settled = false
			qc.on('ready', () => {
				if (settled) return
				settled = true
				conn.alpn = 'h3'
				conn.h3Client = new H3Client(qc)
				qc.on('error', (e) => this._evict(key, conn))
				resolve(conn)
			})
			qc.on('error', (e) => { if (!settled) { settled = true; reject(e) } })
			qc.connect().catch((e) => { if (!settled) { settled = true; reject(e) } })
		})
	}

	_create(host, port, profile, proxy, key, opts = {}) {
		return new Promise((resolve, reject) => {
			// Auto-PSK resumption: if we have a cached session for this host, offer it.
			// On a fresh handshake the server may reject (e.g., ticket expired or unknown),
			// in which case TLS falls back to a full 1-RTT handshake — no behavioral change
			// for the caller. If the caller also supplied earlyData, it's bundled with the
			// PSK offer for true 0-RTT.
			const sessionIdentity = opts.sessionIdentity || host
			const canResumeSession = !opts.ech?.config
			const session = canResumeSession ? sessionCache.take(sessionIdentity) : null
			const tlsOpts = {
				verifyTLS: opts.verifyTLS !== false,
				connectHost: opts.connectHost || host,
				addressHints: opts.addressHints || null,
				ech: opts.ech || null,
				sessionIdentity,
			}
			if (session) tlsOpts.session = session
			if (opts.earlyData) tlsOpts.earlyData = opts.earlyData
			if (opts.profileObj) tlsOpts.profile = opts.profileObj
			const tls = new TLS(opts.tlsName || host, port, proxy, tlsOpts)
			const conn = this._wrapConnectionClose(new PooledConnection(tls, key), host, port)
			if (session) conn.usedSession = true
			if (opts.earlyData) conn.usedEarlyData = true
			let settled = false
			let connectTimer = null, handshakeTimer = null
			const clearAllTimers = () => {
				if (connectTimer) { clearTimeout(connectTimer); connectTimer = null }
				if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null }
			}
			const fail = (err) => {
				if (settled) return
				settled = true
				clearAllTimers()
				try { tls.socket?.destroy() } catch (_) {}
				reject(err)
			}
			const onReady = (alpn) => {
				if (settled) return
				settled = true
				clearAllTimers()
				conn.alpn = alpn
				conn.h2Session = tls.h2Session ?? null
				conn.h2Transport = tls.h2Transport ?? null
				conn.markUsed()
				if (alpn === 'h2' && conn.h2Session) {
					conn.h2Session.on('close', () => this._evict(key, conn))
					conn.h2Session.on('goaway', () => {
						// stop accepting new streams; let in-flight finish naturally
						conn.closed = true
						this.connections.delete(key)
					})
				}
				resolve(conn)
			}
			tls.on('ready', () => onReady('h2'))
			tls.on('ready-http1', () => onReady('http/1.1'))
			tls.on('error', (e) => fail(e))
			tls.connect().catch((e) => fail(e))

			// Per-phase timeouts. Each is optional; without one the connection inherits
			// only Node's default socket and TLS behavior.
			const timeouts = opts.timeouts || {}
			const { HellojsError } = require('./errors')
			if (timeouts.connect) {
				connectTimer = setTimeout(() => {
					if (!tls.socket || !tls.socket.connecting === false) {
						fail(new HellojsError(`TCP connect timed out after ${timeouts.connect}ms`, 'ETIMEDOUT'))
					}
				}, timeouts.connect)
				connectTimer.unref?.()
				// Once TCP is connected, cancel the connect timer.
				const onConnect = () => { if (connectTimer) { clearTimeout(connectTimer); connectTimer = null } }
				queueMicrotask(() => tls.socket?.once?.('connect', onConnect))
			}
			if (timeouts.tlsHandshake) {
				handshakeTimer = setTimeout(() => {
					fail(new HellojsError(`TLS handshake timed out after ${timeouts.tlsHandshake}ms`, 'ETIMEDOUT'))
				}, timeouts.tlsHandshake)
				handshakeTimer.unref?.()
			}
		})
	}

	_evict(key, conn) {
		if (this.connections.get(key) === conn) this.connections.delete(key)
		conn.close('evict')
	}

	closeAll() {
		for (const [, c] of this.connections) c.close('shutdown')
		this.connections.clear()
	}

	// Graceful drain. Refuses new acquires, waits for all in-flight work to settle, then
	// closes. Returns when the drain finishes naturally OR the timeoutMs deadline hits (in
	// which case in-flight is forcefully aborted via close('shutdown')).
	//
	// "In-flight work" = pending handshakes + active requests on pooled connections. We must
	// wait for both: a request that's still in handshake won't yet be counted in any
	// connection's activeRequests counter.
	async shutdown(timeoutMs = 30_000) {
		this._draining = true
		const deadline = Date.now() + timeoutMs
		while (Date.now() < deadline) {
			let active = 0
			for (const [, c] of this.connections) active += c.activeRequests
			const pending = this.pending.size
			if (active === 0 && pending === 0) break
			await new Promise((r) => setTimeout(r, 25))
		}
		this.closeAll()
		this._draining = false
	}
}

const defaultPool = new Pool()

// Alt-Svc helpers
function recordAltSvc(host, value) {
	// Parse Alt-Svc header. Look for `h3=":443"; ma=N` or `h3=":443"`. Multiple alternatives allowed.
	if (!value || value === 'clear') { altSvcCache.delete(host); return }
	const m = value.match(/h3="?:?(\d+)"?(?:[^,]*?ma=(\d+))?/i)
	if (m) {
		const port = parseInt(m[1], 10)
		const maxAge = m[2] ? parseInt(m[2], 10) : 86400
		altSvcCache.set(host, { port, expiry: Date.now() + maxAge * 1000 })
	}
}
function lookupAltSvc(host) {
	const e = altSvcCache.get(host)
	if (!e) return null
	if (e.expiry < Date.now()) { altSvcCache.delete(host); return null }
	return e
}
function clearAltSvc() { altSvcCache.clear() }

module.exports = { Pool, PooledConnection, defaultPool, recordAltSvc, lookupAltSvc, clearAltSvc }
