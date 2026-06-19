// HTTP/3 layer (RFC 9114) on top of our QUIC connection.
//
// Streams:
//   - Control stream (client-initiated unidirectional, type 0x00) carries SETTINGS
//   - QPACK encoder stream (uni, type 0x02) — we send empty; we never insert into dynamic table
//   - QPACK decoder stream (uni, type 0x03) — we send empty
//   - Request streams (client-initiated bidirectional) carry HEADERS + DATA frames
//
// Frame types (RFC 9114 §7):
//   0x00 DATA       — request/response body bytes
//   0x01 HEADERS    — QPACK-encoded field section
//   0x04 SETTINGS   — connection settings
//   0x07 GOAWAY
//   0x0d MAX_PUSH_ID

const varint = require('./varint')
const qpack = require('./qpack')

const FRAME = {
	DATA: 0x00,
	HEADERS: 0x01,
	SETTINGS: 0x04,
	GOAWAY: 0x07,
	MAX_PUSH_ID: 0x0d,
}

// Chrome 147 h3 SETTINGS — captured/inferred values:
//   QPACK_MAX_TABLE_CAPACITY (0x01) = 65536
//   MAX_FIELD_SECTION_SIZE (0x06) = 65536
//   QPACK_BLOCKED_STREAMS (0x07) = 100
//   plus a GREASE setting (0x1c through 0x21 randomly chosen)
const CHROME_147_SETTINGS = [
	[0x01, 65536],
	[0x06, 65536],
	[0x07, 100],
]

function encodeFrame(type, payload) {
	return Buffer.concat([varint.encode(type), varint.encode(payload.length), payload])
}

function encodeSettings(settings = CHROME_147_SETTINGS) {
	const parts = []
	for (const [id, value] of settings) {
		parts.push(varint.encode(id))
		parts.push(varint.encode(value))
	}
	return encodeFrame(FRAME.SETTINGS, Buffer.concat(parts))
}

class H3Client {
	constructor(quicConn) {
		this.conn = quicConn
		this.controlStream = null
		this.encoderStream = null
		this.decoderStream = null
		this.bootstrapped = false

		// QPACK dynamic table replica — populated from server's encoder stream.
		this.peerDynamicTable = new qpack.DynamicTable()
		this.peerEncoderBuf = Buffer.alloc(0)
		this.peerQpackMaxTableCapacity = 0   // populated when we see server SETTINGS

		// Hook server-initiated unidirectional streams (control / encoder / decoder).
		this.conn.onServerStream = (stream) => this._onServerUniStream(stream)
	}

	_onServerUniStream(stream) {
		let typeBuf = Buffer.alloc(0)
		let streamType = null
		stream.on('data', (chunk) => {
			if (streamType == null) {
				typeBuf = Buffer.concat([typeBuf, chunk])
				try {
					const v = varint.decode(typeBuf, 0)
					streamType = v.value
					const after = typeBuf.subarray(v.length)
					if (streamType === 0x02) {
						this.peerEncoderBuf = Buffer.concat([this.peerEncoderBuf, after])
						this._drainPeerEncoder()
					}
					// 0x00 = control, 0x03 = decoder — we don't use these for anything yet.
					return
				} catch (_) {
					return  // need more bytes for varint
				}
			}
			if (streamType === 0x02) {
				this.peerEncoderBuf = Buffer.concat([this.peerEncoderBuf, chunk])
				this._drainPeerEncoder()
			}
		})
	}

	_drainPeerEncoder() {
		try {
			const consumed = qpack.parseEncoderInstructions(this.peerEncoderBuf, this.peerDynamicTable)
			if (consumed > 0) this.peerEncoderBuf = this.peerEncoderBuf.subarray(consumed)
		} catch (_) {
			// Malformed QPACK encoder stream — drop it rather than crash the process.
			this.peerEncoderBuf = Buffer.alloc(0)
		}
	}

	bootstrap() {
		// Open the three uni streams: control (type 0x00), encoder (0x02), decoder (0x03).
		this.controlStream = this.conn.openUniStream()
		this.controlStream.send(varint.encode(0x00), false)
		this.controlStream.send(encodeSettings(), false)

		this.encoderStream = this.conn.openUniStream()
		this.encoderStream.send(varint.encode(0x02), false)

		this.decoderStream = this.conn.openUniStream()
		this.decoderStream.send(varint.encode(0x03), false)

		this.bootstrapped = true
	}

	request({ method, path, host, headers = {}, body }) {
		if (!this.bootstrapped) this.bootstrap()
		const stream = this.conn.openBidiStream()

		const ordered = [
			[':method', method],
			[':authority', host],
			[':scheme', 'https'],
			[':path', path],
			...Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
		]
		const fieldSection = qpack.encodeHeaders(ordered)
		const headersFrame = encodeFrame(FRAME.HEADERS, fieldSection)

		const respChunks = []
		const respHeaders = {}
		let respFrameBuf = Buffer.alloc(0)
		let respFailed = false

		// Read a QUIC varint only when all its bytes are present (its length is encoded in the top 2
		// bits of the first byte). Returns null = "need more": varint.decode would otherwise THROW on
		// a multi-byte varint split across packet boundaries, which is ordinary traffic.
		const peekVarint = (b, o) => {
			if (o >= b.length) return null
			const need = 1 << (b[o] >> 6)
			if (o + need > b.length) return null
			return varint.decode(b, o)
		}

		stream.on('data', (data) => {
			if (respFailed) return
			respFrameBuf = Buffer.concat([respFrameBuf, data])
			try {
				while (true) {
					if (respFrameBuf.length === 0) break
					let off = 0
					const t = peekVarint(respFrameBuf, off); if (!t) break; off += t.length
					const l = peekVarint(respFrameBuf, off); if (!l) break; off += l.length
					if (off + l.value > respFrameBuf.length) break
					const payload = respFrameBuf.subarray(off, off + l.value)
					respFrameBuf = respFrameBuf.subarray(off + l.value)
					if (t.value === FRAME.HEADERS) {
						// Prefer dynamic-table-aware decode when the peer's table has entries;
						// fall back to static-only decoder for the static-only path (RIC=0, Base=0).
						const maxEntries = Math.floor((this.peerQpackMaxTableCapacity || this.peerDynamicTable.capacity) / 32)
						const decoded = this.peerDynamicTable.entries.length > 0 || (payload[0] !== 0)
							? qpack.decodeHeadersWithTable(payload, this.peerDynamicTable, maxEntries)
							: qpack.decodeHeaders(payload)
						for (const [n, v] of decoded) respHeaders[n] = v
					} else if (t.value === FRAME.DATA) {
						respChunks.push(Buffer.from(payload))
					}
				}
			} catch (e) {
				// Malformed H3 framing / QPACK from the server: fail this request, don't crash.
				respFailed = true
				const err = new Error(`h3 response parse failed: ${e.message}`)
				err.code = 'EH3PARSE'
				stream.emit('error', err)
			}
		})

		return new Promise((resolve, reject) => {
			stream.on('end', () => {
				resolve({
					status: parseInt(respHeaders[':status'] || '0', 10),
					headers: respHeaders,
					body: Buffer.concat(respChunks),
				})
			})
			stream.on('error', reject)
			if (body) {
				stream.send(headersFrame, false)
				stream.send(encodeFrame(FRAME.DATA, body), true)
			} else {
				stream.send(headersFrame, true)
			}
		})
	}
}

module.exports = { H3Client, encodeSettings, encodeFrame, FRAME, CHROME_147_SETTINGS }
