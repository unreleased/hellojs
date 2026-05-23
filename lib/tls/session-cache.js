// TLS 1.3 session resumption cache (RFC 8446 §4.6.1).
//
// Stores NewSessionTicket material keyed by host so a future handshake to the same origin
// can offer a pre_shared_key extension. Default storage is in-process memory.
//
// Optional persistent storage:
//   require('./session-cache').enablePersistence({ path: '/path/to/sessions.json' })
// or via env: HELLOJS_SESSION_CACHE=/path/to/sessions.json
// Writes are batched (debounced) so the hot path isn't disk-bound.

const fs = require('node:fs')
const path = require('node:path')

const store = new Map()    // host -> Session[] (most-recent first; bounded length)
const MAX_PER_HOST = 4

let persistPath = null
let writeTimer = null
// `dirtyState` tracks per-identity intent for the next flush:
//   - put → ensure the key is included in the merge
//   - take → remember which ticket(s) we consumed so they can be removed from disk
//   - clear → drop on-disk entries for this key entirely
// Without this, a concurrent writer's tickets could be silently dropped by our flush
// (we'd serialize only our own in-memory state and overwrite theirs), or our `take`
// would be reverted by the next merge (because the on-disk copy still has it).
const dirtyState = new Map()
const FLUSH_DEBOUNCE_MS = 250

function _markDirtyPut(key) {
	if (!dirtyState.has(key)) dirtyState.set(key, { clear: false, removedTickets: new Set() })
}

function _markDirtyTake(key, session) {
	let state = dirtyState.get(key)
	if (!state) {
		state = { clear: false, removedTickets: new Set() }
		dirtyState.set(key, state)
	}
	if (session?.ticket) state.removedTickets.add(Buffer.from(session.ticket).toString('base64'))
}

function _markDirtyClear(key) {
	let state = dirtyState.get(key)
	if (!state) {
		state = { clear: true, removedTickets: new Set() }
		dirtyState.set(key, state)
		return
	}
	state.clear = true
	state.removedTickets.clear()
}

function _scheduleFlush() {
	if (!persistPath) return
	if (writeTimer) return
	writeTimer = setTimeout(() => { writeTimer = null; _flush() }, FLUSH_DEBOUNCE_MS).unref?.()
}

function _serialize() {
	const snapshot = {}
	for (const [host, list] of store) {
		snapshot[host] = list.map((s) => ({
			...s,
			ticketNonce: s.ticketNonce.toString('base64'),
			ticket: s.ticket.toString('base64'),
		}))
	}
	return snapshot
}

// Acquire an exclusive on-disk lock by creating `${path}.lock` with O_CREAT|O_EXCL.
// Times out after roughly `LOCK_TIMEOUT_MS`. Stale locks (older than LOCK_STALE_MS,
// e.g., from a crashed process) are forcibly removed.
const LOCK_TIMEOUT_MS = 2000
const LOCK_STALE_MS = 30_000
function _acquireLock(filePath) {
	const lockPath = filePath + '.lock'
	const start = Date.now()
	while (Date.now() - start < LOCK_TIMEOUT_MS) {
		try {
			const fd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600)
			fs.writeSync(fd, String(process.pid))
			fs.closeSync(fd)
			return lockPath
		} catch (e) {
			if (e.code !== 'EEXIST') throw e
			// Check for stale lock
			try {
				const st = fs.statSync(lockPath)
				if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
					fs.unlinkSync(lockPath)
					continue
				}
			} catch (_) { /* lock vanished between checks; try again */ }
			// Brief backoff
			const wait = 10 + Math.floor(Math.random() * 20)
			const until = Date.now() + wait
			while (Date.now() < until) { /* spin */ }
		}
	}
	throw new Error(`session-cache: could not acquire ${lockPath} within ${LOCK_TIMEOUT_MS}ms`)
}

function _releaseLock(lockPath) {
	try { fs.unlinkSync(lockPath) } catch (_) {}
}

// Merge our in-memory store with whatever's on disk, dedup by ticket bytes, and
// write atomically. This is the concurrency guard: two processes pointed at the
// same cache file will see each other's tickets instead of clobbering.
function _flush() {
	if (!persistPath) return
	let lockPath = null
	try {
		fs.mkdirSync(path.dirname(persistPath), { recursive: true })
		lockPath = _acquireLock(persistPath)
		let onDisk = {}
		try {
			const raw = fs.readFileSync(persistPath, 'utf8')
			onDisk = JSON.parse(raw)
		} catch (_) { /* missing or corrupt: ignore */ }
		const ours = _serialize()
		const merged = { ...onDisk }
		const now = Date.now()
		for (const [key, state] of dirtyState) {
			const list = ours[key] || []
			const dest = []
			const seen = new Set()
			for (const entry of list) {
				if (entry.expiresAt && entry.expiresAt < now) continue
				if (!seen.has(entry.ticket)) { dest.push(entry); seen.add(entry.ticket) }
			}
			if (!state.clear) {
				for (const entry of merged[key] || []) {
					if (state.removedTickets.has(entry.ticket)) continue
					if (entry.expiresAt && entry.expiresAt < now) continue
					if (!seen.has(entry.ticket)) { dest.push(entry); seen.add(entry.ticket) }
				}
			}
			if (dest.length > MAX_PER_HOST) dest.length = MAX_PER_HOST
			if (dest.length > 0) merged[key] = dest
			else delete merged[key]
		}
		fs.writeFileSync(persistPath + '.tmp', JSON.stringify(merged), { mode: 0o600 })
		fs.renameSync(persistPath + '.tmp', persistPath)
		dirtyState.clear()
	} catch (_) { /* best-effort; cache loss is recoverable via fresh handshake */ }
	finally {
		if (lockPath) _releaseLock(lockPath)
	}
}

function _load() {
	if (!persistPath) return
	try {
		const raw = fs.readFileSync(persistPath, 'utf8')
		const snapshot = JSON.parse(raw)
		const now = Date.now()
		for (const [host, list] of Object.entries(snapshot)) {
			const valid = list
				.map((s) => ({
					...s,
					ticketNonce: Buffer.from(s.ticketNonce, 'base64'),
					ticket: Buffer.from(s.ticket, 'base64'),
				}))
				.filter((s) => !s.expiresAt || s.expiresAt > now)
			if (valid.length) store.set(host, valid)
		}
	} catch (_) { /* missing or corrupt file: fall back to fresh cache */ }
}

function enablePersistence({ path: p }) {
	persistPath = p
	_load()
}

if (process.env.HELLOJS_SESSION_CACHE) {
	enablePersistence({ path: process.env.HELLOJS_SESSION_CACHE })
}

// Logical identity → cache key.
// Tickets are partitioned so that resumption never crosses these boundaries:
//   - plain { host }                                       → `host`
//   - { host, publicName } (e.g. SNI override, no ECH)     → `public-name|host|publicName`
//   - { host, ech: true, publicName? }                     → `ech|host[|publicName]`
// String identities are accepted unchanged for backwards compatibility with callers that
// just pass a hostname.
function keyOf(identity) {
	if (typeof identity === 'string') return identity
	if (!identity || typeof identity !== 'object') throw new TypeError('session-cache identity must be a string or object')
	const host = normalizeName(identity.host)
	const rawPublicName = identity.publicName || identity.tlsName || null
	const publicName = rawPublicName ? normalizeName(rawPublicName) : null
	if (identity.ech) return publicName && publicName !== host ? `ech|${host}|${publicName}` : `ech|${host}`
	if (publicName && publicName !== host) return `public-name|${host}|${publicName}`
	return host
}

function normalizeName(name) {
	if (typeof name !== 'string' || name.length === 0) throw new TypeError('session-cache identity host must be a non-empty string')
	return name.toLowerCase()
}

function put(identity, session) {
	const key = keyOf(identity)
	const list = store.get(key) || []
	list.unshift(session)
	if (list.length > MAX_PER_HOST) list.length = MAX_PER_HOST
	store.set(key, list)
	_markDirtyPut(key)
	_scheduleFlush()
}

function take(identity) {
	const key = keyOf(identity)
	const list = store.get(key)
	if (!list || list.length === 0) return null
	const s = list.shift()
	if (list.length === 0) store.delete(key)
	else store.set(key, list)
	_markDirtyTake(key, s)
	if (s.expiresAt && Date.now() > s.expiresAt) return take(identity)
	_scheduleFlush()
	return s
}

function peek(identity) {
	const list = store.get(keyOf(identity))
	return list && list[0] ? list[0] : null
}

function size(identity) {
	return identity ? (store.get(keyOf(identity))?.length || 0) : [...store.values()].reduce((n, l) => n + l.length, 0)
}

function clear(identity) {
	if (identity) {
		const key = keyOf(identity)
		store.delete(key)
		_markDirtyClear(key)
	} else {
		for (const key of store.keys()) _markDirtyClear(key)
		store.clear()
	}
	_scheduleFlush()
}

function flush() { _flush() }

// Parse a TLS 1.3 NewSessionTicket message body (RFC 8446 §4.6.1).
//   uint32 ticket_lifetime; uint32 ticket_age_add; opaque ticket_nonce<0..255>;
//   opaque ticket<1..2^16-1>; Extension extensions<0..2^16-2>;
function parseNewSessionTicket(body) {
	let o = 0
	const ticketLifetime = body.readUInt32BE(o); o += 4    // seconds; 0 = ticket SHOULD be discarded immediately
	const ticketAgeAdd   = body.readUInt32BE(o); o += 4
	const nonceLen       = body[o++]
	const ticketNonce    = body.subarray(o, o + nonceLen); o += nonceLen
	const ticketLen      = body.readUInt16BE(o); o += 2
	const ticket         = body.subarray(o, o + ticketLen); o += ticketLen
	const extLen         = body.readUInt16BE(o); o += 2
	const extensions     = body.subarray(o, o + extLen); o += extLen

	// early_data extension (0x002a) inside NST carries a 4-byte max_early_data_size.
	let maxEarlyDataSize = 0
	let p = 0
	while (p + 4 <= extensions.length) {
		const t = extensions.readUInt16BE(p); p += 2
		const l = extensions.readUInt16BE(p); p += 2
		const d = extensions.subarray(p, p + l); p += l
		if (t === 0x002a && d.length >= 4) maxEarlyDataSize = d.readUInt32BE(0)
	}

	return {
		ticketLifetime,
		ticketAgeAdd,
		ticketNonce: Buffer.from(ticketNonce),
		ticket: Buffer.from(ticket),
		maxEarlyDataSize,
		issuedAt: Date.now(),
		expiresAt: ticketLifetime > 0 ? Date.now() + ticketLifetime * 1000 : 0,
	}
}

module.exports = { keyOf, put, take, peek, size, clear, flush, enablePersistence, parseNewSessionTicket }
