// Minimal HTTP/2 session implementation. Replaces Node's http2.connect() on the hot
// path so we can cut session-setup overhead and so we control the on-wire details
// for Chrome-fingerprint fidelity.
//
// Scope:
//   - SETTINGS exchange + ACK
//   - HEADERS frame send/receive (single frame — no CONTINUATION yet)
//   - DATA frame send/receive with flow control (we advertise a huge window so we
//     never have to throttle our receive side; we respect peer's window on send)
//   - WINDOW_UPDATE auto-replenish
//   - PING auto-response
//   - RST_STREAM handling
//   - GOAWAY handling (stop opening new streams, let in-flight finish)
//
// Not implemented:
//   - Server push (we set ENABLE_PUSH=0 in our SETTINGS)
//   - HEADERS continuation across multiple frames (rare; would only hit if a single
//     response had > MAX_FRAME_SIZE worth of header bytes)
//   - Priority frame parsing (we ignore peer priority; we send fixed Chrome-like values
//     in our HEADERS flags)

const { EventEmitter } = require('events')
const frame = require('./frame')
const hpack = require('./hpack')

const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

// Chrome 147 client SETTINGS (matches the wire fingerprint). Used as the fallback when no
// profile is supplied or a profile omits http2.settings.
const CHROME_147_SETTINGS = [
	[frame.SETTING.HEADER_TABLE_SIZE, 65536],
	[frame.SETTING.ENABLE_PUSH, 0],
	[frame.SETTING.INITIAL_WINDOW_SIZE, 6291456],
	[frame.SETTING.MAX_HEADER_LIST_SIZE, 262144],
]
const CHROME_WINDOW_UPDATE = 15663105   // adds to the initial 65535

// Map from profile.http2.settings property names (insertion-order preserved by JS) to wire
// IDs. Properties not in this map are silently ignored so a profile can carry extra info
// without breaking the codec.
const SETTING_NAME_TO_ID = {
	headerTableSize:       frame.SETTING.HEADER_TABLE_SIZE,
	enablePush:            frame.SETTING.ENABLE_PUSH,
	maxConcurrentStreams:  frame.SETTING.MAX_CONCURRENT_STREAMS,
	initialWindowSize:     frame.SETTING.INITIAL_WINDOW_SIZE,
	maxFrameSize:          frame.SETTING.MAX_FRAME_SIZE,
	maxHeaderListSize:     frame.SETTING.MAX_HEADER_LIST_SIZE,
	noRfc7540Priorities:   frame.SETTING.NO_RFC7540_PRIORITIES,
}

// Translate profile.http2.settings (object with insertion-order-significant keys) into the
// wire pairs the SETTINGS frame builder expects. Booleans collapse to 0/1.
function settingsFromProfile(profile) {
	const s = profile?.http2?.settings
	if (!s) return CHROME_147_SETTINGS
	const pairs = []
	for (const [name, val] of Object.entries(s)) {
		const id = SETTING_NAME_TO_ID[name]
		if (id == null) continue
		const num = typeof val === 'boolean' ? (val ? 1 : 0) : (val >>> 0)
		pairs.push([id, num])
	}
	return pairs.length ? pairs : CHROME_147_SETTINGS
}

class H2Stream extends EventEmitter {
	constructor(session, id) {
		super()
		this.session = session
		this.id = id
		this.closed = false
		this._buf = Buffer.alloc(0)
		this._endRecvd = false
		// HEADERS may be followed by CONTINUATION frames if the header block exceeds one
		// frame. We accumulate the fragments here and finalize on END_HEADERS.
		this._headerFragments = null
		this._headerEndStream = false
		// Per-stream flow control windows (RFC 7540 §6.9).
		// `sendWindow` shrinks as we send DATA; refilled by inbound WINDOW_UPDATE for this stream.
		// `recvUsed` accumulates received DATA bytes; we refill via outbound WINDOW_UPDATE.
		this.sendWindow = 65535
		this.recvUsed   = 0
	}
	_onHeaders(payload, flags) {
		// HEADERS may have PADDED or PRIORITY flags affecting payload layout.
		let p = payload
		if (flags & frame.FLAG.PADDED) {
			const padLen = p[0]
			p = p.subarray(1, p.length - padLen)
		}
		if (flags & frame.FLAG.PRIORITY) {
			p = p.subarray(5)   // skip 5 bytes of priority info
		}
		this._headerFragments = [Buffer.from(p)]
		this._headerBytes = p.length
		this._headerEndStream = !!(flags & frame.FLAG.END_STREAM)
		if (flags & frame.FLAG.END_HEADERS) this._finalizeHeaders()
	}
	_onContinuation(payload, flags) {
		if (!this._headerFragments) {
			// CONTINUATION without preceding HEADERS — protocol error
			this.session._sendFrame(frame.TYPE.RST_STREAM, 0, this.id, frame.buildRstStream(frame.ERROR.PROTOCOL_ERROR))
			return
		}
		this._headerFragments.push(Buffer.from(payload))
		// Bound the compressed header block to defend against a CONTINUATION flood (unbounded
		// fragment accumulation before END_HEADERS — the CVE-2024-27316 class).
		this._headerBytes = (this._headerBytes || 0) + payload.length
		if (this._headerBytes > 262144) {
			return this.session._fatalError(Object.assign(new Error('header block too large'), { code: 'EH2COMPRESS' }))
		}
		if (flags & frame.FLAG.END_HEADERS) this._finalizeHeaders()
	}
	_finalizeHeaders() {
		const block = this._headerFragments.length === 1
			? this._headerFragments[0]
			: Buffer.concat(this._headerFragments)
		this._headerFragments = null
		const list = hpack.decode(block, this.session.peerHpackTable)
		const headers = {}
		for (const [n, v] of list) headers[n] = headers[n] != null ? [].concat(headers[n], v) : v
		this.emit('response', headers)
		if (this._headerEndStream) this._endStream()
	}
	_onData(payload, flags) {
		this.emit('data', payload)
		// Auto-replenish flow control on the stream + connection.
		this.recvUsed += payload.length
		this.session._creditFlow(this.id, payload.length)
		// Per-stream replenish: when this stream has consumed >32KB, issue a stream WINDOW_UPDATE.
		if (this.recvUsed >= 32768) {
			this.session._sendFrame(frame.TYPE.WINDOW_UPDATE, 0, this.id, frame.buildWindowUpdate(this.recvUsed))
			this.recvUsed = 0
		}
		if (flags & frame.FLAG.END_STREAM) this._endStream()
	}
	_endStream() {
		if (this._endRecvd) return
		this._endRecvd = true
		this.closed = true
		this.session._closeStream(this.id)
		this.emit('end')
	}
	_onRst(errorCode) {
		this.closed = true
		this.session._closeStream(this.id)
		const err = new Error(`stream reset by peer (code=${errorCode})`)
		err.code = 'EH2STREAM'
		err.errorCode = errorCode
		this.emit('error', err)
	}
	// Public API
	write(chunk) {
		if (!chunk || chunk.length === 0) return
		this.session._sendData(this.id, chunk, false)
		this._wroteBody = true
	}
	end(body) {
		if (body) { this.session._sendData(this.id, body, true); this._wroteBody = true; return }
		// If we've streamed any body chunks already, terminate the stream with an empty
		// END_STREAM DATA frame. Otherwise the HEADERS frame already carried END_STREAM
		// (set by session.request({ endStream: true })) and a trailing zero-length DATA
		// would be a protocol error.
		if (this._wroteBody) this.session._sendData(this.id, Buffer.alloc(0), true)
	}
	close(errorCode = 0x08) {
		if (this.closed) return
		this.closed = true
		this.session._sendFrame(frame.TYPE.RST_STREAM, 0, this.id, frame.buildRstStream(errorCode))
		this.session._closeStream(this.id)
	}
}

class H2Session extends EventEmitter {
	constructor(transport, profile = null) {
		super()
		this.transport = transport
		this.profile = profile
		this.streams = new Map()
		this.nextStreamId = 1
		this._rxBuf = Buffer.alloc(0)
		this._sawSettings = false

		this._localSettings = settingsFromProfile(profile)
		this._windowUpdateIncrement = profile?.http2?.windowUpdateIncrement ?? CHROME_WINDOW_UPDATE

		this.peerSettings = {
			[frame.SETTING.HEADER_TABLE_SIZE]: 4096,
			[frame.SETTING.MAX_CONCURRENT_STREAMS]: Infinity,
			[frame.SETTING.INITIAL_WINDOW_SIZE]: 65535,
			[frame.SETTING.MAX_FRAME_SIZE]: 16384,
		}
		// Connection-level send window — limited by peer.
		this._connSendWindow = 65535
		// Connection-level receive window — we restore aggressively.
		this._connRecvWindow = 65535 + this._windowUpdateIncrement
		this._connRecvUsed = 0

		// HPACK tables. Encoder uses ours, decoder uses peer's. Capacities track each SETTINGS.
		this.localHpackTable = new hpack.DynamicTable(65536)
		this.peerHpackTable = new hpack.DynamicTable(4096)

		this.closed = false
		this.destroyed = false

		transport.on('data', (chunk) => this._onData(chunk))
		transport.on('end', () => this._onTransportClose())
		transport.on('error', (e) => this.emit('error', e))

		this._sendPreface()
	}

	_sendPreface() {
		const settings = frame.build(frame.TYPE.SETTINGS, 0, 0, frame.buildSettings(this._localSettings))
		const winUpdate = frame.build(frame.TYPE.WINDOW_UPDATE, 0, 0, frame.buildWindowUpdate(this._windowUpdateIncrement))
		// Single write so the preface + SETTINGS + WINDOW_UPDATE land in one application_data
		// record, matching the browser fingerprint.
		this.transport.write(Buffer.concat([H2_PREFACE, settings, winUpdate]))
	}

	_sendFrame(type, flags, streamId, payload) {
		this.transport.write(frame.build(type, flags, streamId, payload))
	}

	_onData(chunk) {
		this._rxBuf = Buffer.concat([this._rxBuf, chunk])
		// Malformed frames / header blocks (HPACK errors, bad lengths) from the peer must not crash
		// the process by throwing out of this transport 'data' handler. An HPACK error desyncs the
		// dynamic table for the whole connection, so any throw here is a fatal connection error.
		try {
			while (true) {
				const f = frame.parse(this._rxBuf)
				if (!f) break
				this._rxBuf = this._rxBuf.subarray(f.consumed)
				this._dispatch(f)
			}
		} catch (e) {
			this._fatalError(e)
		}
	}

	// Fail all in-flight streams (callers listen via req.on('error')) and tear the session down.
	// We do NOT emit a session 'error' — nothing listens for it, so that would itself throw.
	_fatalError(err) {
		if (this.destroyed) return
		this.destroyed = true
		this.closed = true
		const e = new Error(`h2 connection error: ${err.message}`)
		e.code = err.code || 'EH2PROTOCOL'
		for (const s of [...this.streams.values()]) {
			s.closed = true
			try { s.emit('error', e) } catch (_) { /* stream without an error listener */ }
		}
		this.streams.clear()
		try { this._sendFrame(frame.TYPE.GOAWAY, 0, 0, frame.buildGoaway(0, frame.ERROR.PROTOCOL_ERROR)) } catch (_) {}
		try { this.transport.destroy?.() } catch (_) {}
		this.emit('close')
	}

	_dispatch(f) {
		switch (f.type) {
			case frame.TYPE.SETTINGS:
				if (f.flags & frame.FLAG.ACK) break
				for (const [id, v] of frame.parseSettings(f.payload)) {
					this.peerSettings[id] = v
					if (id === frame.SETTING.HEADER_TABLE_SIZE) {
						// Peer is telling us their decoder capacity for the headers WE encode.
						this.localHpackTable.setCapacity(v)
					}
				}
				this._sendFrame(frame.TYPE.SETTINGS, frame.FLAG.ACK, 0, Buffer.alloc(0))
				if (!this._sawSettings) {
					this._sawSettings = true
					this.emit('connect')
				}
				break
			case frame.TYPE.WINDOW_UPDATE: {
				const inc = f.payload.readUInt32BE(0) & 0x7fffffff
				if (f.streamId === 0) {
					this._connSendWindow += inc
				} else {
					const s = this.streams.get(f.streamId)
					if (s) s.sendWindow += inc
				}
				break
			}
			case frame.TYPE.HEADERS: {
				const s = this.streams.get(f.streamId)
				if (s) s._onHeaders(f.payload, f.flags)
				break
			}
			case frame.TYPE.CONTINUATION: {
				const s = this.streams.get(f.streamId)
				if (s) s._onContinuation(f.payload, f.flags)
				break
			}
			case frame.TYPE.DATA: {
				let p = f.payload
				if (f.flags & frame.FLAG.PADDED) {
					const padLen = p[0]
					p = p.subarray(1, p.length - padLen)
				}
				const s = this.streams.get(f.streamId)
				if (s) s._onData(p, f.flags)
				else this._creditFlow(0, p.length)   // unknown stream — still credit the conn window
				break
			}
			case frame.TYPE.RST_STREAM: {
				const code = f.payload.readUInt32BE(0)
				const s = this.streams.get(f.streamId)
				if (s) s._onRst(code)
				break
			}
			case frame.TYPE.PING:
				if (!(f.flags & frame.FLAG.ACK)) {
					this._sendFrame(frame.TYPE.PING, frame.FLAG.ACK, 0, f.payload)
				}
				break
			case frame.TYPE.GOAWAY: {
				const g = frame.parseGoaway(f.payload)
				this.emit('goaway', g.errorCode, g.lastStreamId)
				this.closed = true
				break
			}
			case frame.TYPE.PUSH_PROMISE:
				// We set ENABLE_PUSH=0 so this should never happen; if it does, reset the stream.
				this._sendFrame(frame.TYPE.RST_STREAM, 0, f.streamId, frame.buildRstStream(frame.ERROR.PROTOCOL_ERROR))
				break
		}
	}

	_creditFlow(streamId, bytes) {
		this._connRecvUsed += bytes
		// Replenish in big chunks to amortize.
		if (this._connRecvUsed >= 65536) {
			this._sendFrame(frame.TYPE.WINDOW_UPDATE, 0, 0, frame.buildWindowUpdate(this._connRecvUsed))
			this._connRecvUsed = 0
		}
	}

	_sendData(streamId, body, endStream) {
		const buf = Buffer.isBuffer(body) ? body : Buffer.from(body)
		const maxFrame = Math.min(this.peerSettings[frame.SETTING.MAX_FRAME_SIZE] || 16384, 16384)
		const stream = this.streams.get(streamId)
		let off = 0
		while (off < buf.length) {
			// Respect per-stream + connection send windows. RFC 7540 §6.9.1: a sender MUST NOT
			// send DATA frames larger than min(connWindow, streamWindow). For now we just send
			// what we have and decrement; if a window goes negative we'd need to buffer — but
			// in practice with maxFrame=16KB and 64KB initial windows, single-shot requests
			// never block. For sustained streaming uploads this needs queuing; that's a future
			// item documented in README.
			const room = Math.min(
				maxFrame,
				this._connSendWindow,
				stream ? stream.sendWindow : maxFrame,
			)
			if (room <= 0) break  // window exhausted; drop the rest (caller sees short write)
			const take = Math.min(maxFrame, buf.length - off, room)
			const chunk = buf.subarray(off, off + take)
			off += chunk.length
			const flags = (off >= buf.length && endStream) ? frame.FLAG.END_STREAM : 0
			this._sendFrame(frame.TYPE.DATA, flags, streamId, chunk)
			this._connSendWindow -= chunk.length
			if (stream) stream.sendWindow -= chunk.length
		}
		if (buf.length === 0 && endStream) {
			this._sendFrame(frame.TYPE.DATA, frame.FLAG.END_STREAM, streamId, Buffer.alloc(0))
		}
	}

	_closeStream(id) {
		this.streams.delete(id)
	}

	_onTransportClose() {
		this.closed = true
		this.destroyed = true
		this.emit('close')
	}

	// Public API (mirrors enough of Node's http2.ClientHttp2Session that lib/client.js can drive it).
	request(headers, opts = {}) {
		const id = this.nextStreamId
		this.nextStreamId += 2
		const stream = new H2Stream(this, id)
		this.streams.set(id, stream)

		// Normalize: lib/client.js passes headers as { ':method': 'GET', ... } object.
		const list = []
		for (const [k, v] of Object.entries(headers)) {
			if (Array.isArray(v)) for (const vv of v) list.push([k, vv])
			else list.push([k, v])
		}
		const block = hpack.encode(list, this.localHpackTable)
		const endStream = !!opts.endStream
		// PRIORITY-on-HEADERS is profile-driven. Chrome 147 sets it with E=1, weight=256.
		// Safari clears the flag (it advertises NO_RFC7540_PRIORITIES). When the profile says
		// sendPriorityFrame is false we omit the flag and the 5-byte payload entirely.
		const profPri = this.profile?.http2 || {}
		const sendPri = opts.weight != null || opts.exclusive != null || opts.parent != null
			? true
			: profPri.sendPriorityFrame !== false && profPri.priority != null
		let payload = block
		let flags = frame.FLAG.END_HEADERS | (endStream ? frame.FLAG.END_STREAM : 0)
		if (sendPri) {
			const dflt = profPri.priority || { weight: 256, exclusive: true, parent: 0 }
			const weight = ((opts.weight ?? dflt.weight ?? 256) - 1) & 0xff
			const parent = (opts.parent ?? dflt.parent ?? 0) >>> 0
			const excBool = opts.exclusive != null ? opts.exclusive : dflt.exclusive
			const exclusive = excBool ? 0x80000000 : 0
			const pri = Buffer.alloc(5)
			pri.writeUInt32BE((parent | exclusive) >>> 0, 0)
			pri[4] = weight
			payload = Buffer.concat([pri, block])
			flags |= frame.FLAG.PRIORITY
		}
		// If the header block + (optional) priority payload exceeds MAX_FRAME_SIZE, split into
		// HEADERS + CONTINUATION frame(s). RFC 7540 §6.10: continuations carry the rest of the
		// header block; END_HEADERS lands on the FINAL frame; END_STREAM stays on HEADERS.
		const maxFrame = Math.min(this.peerSettings[frame.SETTING.MAX_FRAME_SIZE] || 16384, 16384)
		if (payload.length > maxFrame) {
			const first = payload.subarray(0, maxFrame)
			// HEADERS gets END_STREAM (if applicable) but NOT END_HEADERS — that comes on the last CONT.
			const firstFlags = flags & ~frame.FLAG.END_HEADERS
			this._sendFrame(frame.TYPE.HEADERS, firstFlags, id, first)
			let off = maxFrame
			while (off < payload.length) {
				const chunk = payload.subarray(off, off + maxFrame)
				off += chunk.length
				const last = off >= payload.length
				this._sendFrame(frame.TYPE.CONTINUATION, last ? frame.FLAG.END_HEADERS : 0, id, chunk)
			}
		} else {
			this._sendFrame(frame.TYPE.HEADERS, flags, id, payload)
		}
		return stream
	}

	close() {
		if (this.closed) return
		this.closed = true
		try {
			this._sendFrame(frame.TYPE.GOAWAY, 0, 0, frame.buildGoaway(0, frame.ERROR.NO_ERROR))
		} catch (_) {}
		this.destroyed = true
		this.emit('close')
	}
}

module.exports = { H2Session, H2Stream, H2_PREFACE, CHROME_147_SETTINGS, CHROME_WINDOW_UPDATE }
