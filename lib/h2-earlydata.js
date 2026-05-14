// HTTP/2 early-data encoder for TLS 1.3 0-RTT (RFC 8470 §4).
//
// Synthesises the byte sequence Chrome sends as 0-RTT on a resumed h2 session:
//   1. The h2 connection preface (24 bytes).
//   2. A SETTINGS frame matching the Chrome 147 profile.
//   3. A WINDOW_UPDATE frame on stream 0 (connection-wide window increment).
//   4. A HEADERS frame on stream 1 with END_HEADERS + END_STREAM (no body).
//
// The HEADERS payload is HPACK (RFC 7541) — separate from QPACK in our h3 layer.
// We use static-table-only encoding (no dynamic table maintenance), Huffman strings.
// That's RFC-compliant and matches what's safe to do for a one-shot request.
//
// CAVEAT (read this carefully):
//   This module returns BYTES to pass as opts.earlyData. The server will see your
//   complete request before the handshake finishes — but the response comes back on
//   stream 1, which Node's built-in http2 module knows nothing about. Our request()
//   API uses Node's http2 for the 1-RTT path and cannot observe stream 1 once the
//   handshake completes. So:
//
//     - Use this helper if you have your own h2 frame parser (or are using a raw
//       TLS connection and parsing frames manually).
//     - DO NOT expect request({ earlyData }) to return the 0-RTT response over h2 —
//       it won't. The bytes are delivered; the response is invisible to Node's http2.
//
//   Real h2 0-RTT response handling would require replacing Node's http2 entirely.
//   See the README's "Session resumption + 0-RTT" section for the full discussion.

const huffman = require('./h3/huffman')

const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

// HPACK static table (RFC 7541 Appendix A). 1-indexed; entry 0 is unused.
const HPACK_STATIC = [
	null,
	[':authority', ''],
	[':method', 'GET'],
	[':method', 'POST'],
	[':path', '/'],
	[':path', '/index.html'],
	[':scheme', 'http'],
	[':scheme', 'https'],
	[':status', '200'],
	[':status', '204'],
	[':status', '206'],
	[':status', '304'],
	[':status', '400'],
	[':status', '404'],
	[':status', '500'],
	['accept-charset', ''],
	['accept-encoding', 'gzip, deflate'],
	['accept-language', ''],
	['accept-ranges', ''],
	['accept', ''],
	['access-control-allow-origin', ''],
	['age', ''],
	['allow', ''],
	['authorization', ''],
	['cache-control', ''],
	['content-disposition', ''],
	['content-encoding', ''],
	['content-language', ''],
	['content-length', ''],
	['content-location', ''],
	['content-range', ''],
	['content-type', ''],
	['cookie', ''],
	['date', ''],
	['etag', ''],
	['expect', ''],
	['expires', ''],
	['from', ''],
	['host', ''],
	['if-match', ''],
	['if-modified-since', ''],
	['if-none-match', ''],
	['if-range', ''],
	['if-unmodified-since', ''],
	['last-modified', ''],
	['link', ''],
	['location', ''],
	['max-forwards', ''],
	['proxy-authenticate', ''],
	['proxy-authorization', ''],
	['range', ''],
	['referer', ''],
	['refresh', ''],
	['retry-after', ''],
	['server', ''],
	['set-cookie', ''],
	['strict-transport-security', ''],
	['transfer-encoding', ''],
	['user-agent', ''],
	['vary', ''],
	['via', ''],
	['www-authenticate', ''],
]

// HPACK integer encoding (RFC 7541 §5.1).
function encodeInt(value, prefixBits, firstByteBase) {
	const max = (1 << prefixBits) - 1
	if (value < max) return Buffer.from([firstByteBase | value])
	const out = [firstByteBase | max]
	value -= max
	while (value >= 128) { out.push((value & 0x7f) | 0x80); value >>>= 7 }
	out.push(value)
	return Buffer.from(out)
}

// HPACK string literal: 1-bit Huffman flag in the top bit of the length-prefix's first
// byte (so prefixBits=7, firstByteBase=0x80 for Huffman; 0x00 for raw).
function encodeStringLiteral(s) {
	const raw = Buffer.from(s, 'utf8')
	const huff = huffman.encode(raw)
	if (huff.length < raw.length) {
		return Buffer.concat([encodeInt(huff.length, 7, 0x80), huff])
	}
	return Buffer.concat([encodeInt(raw.length, 7, 0x00), raw])
}

function findStatic(name, value) {
	let nameIdx = -1
	for (let i = 1; i < HPACK_STATIC.length; i++) {
		const [n, v] = HPACK_STATIC[i]
		if (n === name) {
			if (v === value) return { exact: i }
			if (nameIdx < 0) nameIdx = i
		}
	}
	return nameIdx >= 0 ? { nameOnly: nameIdx } : null
}

// HPACK-encode a header list ([[name, value], ...]) using static table + Huffman strings.
// We always emit "Literal Field Without Indexing" for misses so we never grow the dynamic
// table — keeps the encoder stateless and matches what real Chrome does for one-shots.
function hpackEncode(headers) {
	const out = []
	for (const [n, v] of headers) {
		const name = n.toLowerCase()
		const m = findStatic(name, v)
		if (m && m.exact != null) {
			// Indexed Header Field: 1xxxxxxx (7-bit prefix)
			out.push(encodeInt(m.exact, 7, 0x80))
		} else if (m && m.nameOnly != null) {
			// Literal Without Indexing, indexed name: 0000xxxx (4-bit prefix)
			out.push(encodeInt(m.nameOnly, 4, 0x00))
			out.push(encodeStringLiteral(v))
		} else {
			// Literal Without Indexing, literal name: 0000_0000, then name, then value
			out.push(Buffer.from([0x00]))
			out.push(encodeStringLiteral(name))
			out.push(encodeStringLiteral(v))
		}
	}
	return Buffer.concat(out)
}

// h2 frame header: u24 length, u8 type, u8 flags, u32 stream_id (top bit reserved).
function buildFrame(type, flags, streamId, payload) {
	const hdr = Buffer.alloc(9)
	hdr.writeUIntBE(payload.length, 0, 3)
	hdr[3] = type
	hdr[4] = flags
	hdr.writeUInt32BE(streamId & 0x7fffffff, 5)
	return Buffer.concat([hdr, payload])
}

// SETTINGS frame (type 0x04). Payload = repeated { u16 id, u32 value }.
function encodeSettingsFrame(pairs) {
	const buf = Buffer.alloc(6 * pairs.length)
	let o = 0
	for (const [id, val] of pairs) {
		buf.writeUInt16BE(id, o); o += 2
		buf.writeUInt32BE(val >>> 0, o); o += 4
	}
	return buildFrame(0x04, 0x00, 0, buf)
}

// WINDOW_UPDATE frame (type 0x08). Payload = u32 increment.
function encodeWindowUpdateFrame(streamId, increment) {
	const p = Buffer.alloc(4); p.writeUInt32BE(increment >>> 0, 0)
	return buildFrame(0x08, 0x00, streamId, p)
}

// HEADERS frame (type 0x01). flags: 0x01 END_STREAM, 0x04 END_HEADERS.
function encodeHeadersFrame(streamId, headerList, { endStream = true } = {}) {
	const block = hpackEncode(headerList)
	const flags = 0x04 | (endStream ? 0x01 : 0x00)
	return buildFrame(0x01, flags, streamId, block)
}

// Chrome 147 h2 SETTINGS values + ordering (matches our h2 fingerprint profile).
const CHROME_147_SETTINGS = [
	[0x01, 65536],         // HEADER_TABLE_SIZE
	[0x02, 0],             // ENABLE_PUSH = 0
	[0x04, 6291456],       // INITIAL_WINDOW_SIZE
	[0x06, 262144],        // MAX_HEADER_LIST_SIZE
]
const CHROME_CONN_WINDOW_INCREMENT = 15663105

// Public: synthesise the 0-RTT byte sequence for a single bodyless h2 request.
//   method:  HTTP method (default 'GET')
//   path:    request path
//   host:    :authority value
//   headers: extra header pairs ({ name: value }) merged after the pseudo-headers
//
// Returns a Buffer ready to pass as opts.earlyData. The bytes contain:
//   PREFACE || SETTINGS || WINDOW_UPDATE || HEADERS(END_HEADERS|END_STREAM, stream 1)
//
// IMPORTANT: only safe for replay-tolerant methods (GET, HEAD, OPTIONS) per RFC 8470.
function encodeH2EarlyData({ method = 'GET', path = '/', host, headers = {} }) {
	if (!host) throw new Error('encodeH2EarlyData: host is required')
	const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
	if (!safeMethods.has(method.toUpperCase())) {
		throw new Error(`encodeH2EarlyData: ${method} is not idempotent — 0-RTT replay is unsafe (RFC 8470). Use GET / HEAD / OPTIONS only.`)
	}
	const headerList = [
		[':method', method.toUpperCase()],
		[':authority', host],
		[':scheme', 'https'],
		[':path', path],
		...Object.entries(headers).map(([k, v]) => [String(k).toLowerCase(), String(v)]),
	]
	return Buffer.concat([
		H2_PREFACE,
		encodeSettingsFrame(CHROME_147_SETTINGS),
		encodeWindowUpdateFrame(0, CHROME_CONN_WINDOW_INCREMENT),
		encodeHeadersFrame(1, headerList, { endStream: true }),
	])
}

module.exports = {
	encodeH2EarlyData,
	// Lower-level pieces exposed for advanced callers / testing
	hpackEncode,
	encodeSettingsFrame,
	encodeWindowUpdateFrame,
	encodeHeadersFrame,
	H2_PREFACE,
	HPACK_STATIC,
}
