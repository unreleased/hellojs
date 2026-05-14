// HPACK (RFC 7541) — full encoder + decoder.
//
// Differences vs QPACK:
//   - No Required Insert Count / Base — dynamic table state is per-direction and
//     mutated inline in each header block.
//   - Indexed Header Field: 1xxxxxxx (7-bit index, references static OR dynamic).
//   - Literal With Incremental Indexing: 01xxxxxx — adds entry to dynamic table.
//   - Literal Without Indexing: 0000xxxx.
//   - Literal Never Indexed: 0001xxxx.
//   - Dynamic Table Size Update: 001xxxxx.
//
// We use the static table (RFC 7541 Appendix A) + a dynamic table per session.

const huffman = require('../h3/huffman')

const STATIC = [
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

const STATIC_LEN = STATIC.length - 1   // 61

class DynamicTable {
	constructor(capacity = 4096) {
		this.entries = []   // newest first (index 1 = newest in spec, so [0] is newest)
		this.capacity = capacity
		this.size = 0
	}
	add(name, value) {
		const cost = name.length + value.length + 32
		this.entries.unshift([name, value])
		this.size += cost
		this.evict()
	}
	evict() {
		while (this.size > this.capacity && this.entries.length > 0) {
			const [n, v] = this.entries.pop()
			this.size -= n.length + v.length + 32
		}
	}
	setCapacity(cap) {
		this.capacity = cap
		this.evict()
	}
	// HPACK index space: 1..STATIC_LEN = static, STATIC_LEN+1..STATIC_LEN+entries.length = dynamic.
	lookup(idx) {
		if (idx >= 1 && idx <= STATIC_LEN) return STATIC[idx]
		const d = idx - STATIC_LEN - 1
		return d >= 0 && d < this.entries.length ? this.entries[d] : null
	}
}

// Integer with N-bit prefix (RFC 7541 §5.1).
function encodeInt(value, prefixBits, firstByteBase) {
	const max = (1 << prefixBits) - 1
	if (value < max) return Buffer.from([firstByteBase | value])
	const out = [firstByteBase | max]
	value -= max
	while (value >= 128) { out.push((value & 0x7f) | 0x80); value = Math.floor(value / 128) }
	out.push(value)
	return Buffer.from(out)
}

function decodeInt(buf, off, prefixBits) {
	const max = (1 << prefixBits) - 1
	let v = buf[off] & max
	let o = off + 1
	if (v < max) return { value: v, length: o - off }
	let m = 0
	while (true) {
		const b = buf[o++]
		v += (b & 0x7f) * Math.pow(2, m)
		m += 7
		if ((b & 0x80) === 0) break
	}
	return { value: v, length: o - off }
}

function encodeString(s) {
	const raw = Buffer.from(s, 'utf8')
	const huff = huffman.encode(raw)
	if (huff.length < raw.length) return Buffer.concat([encodeInt(huff.length, 7, 0x80), huff])
	return Buffer.concat([encodeInt(raw.length, 7, 0x00), raw])
}

function decodeString(buf, off) {
	const isHuff = (buf[off] & 0x80) !== 0
	const lenInfo = decodeInt(buf, off, 7)
	const start = off + lenInfo.length
	const raw = buf.subarray(start, start + lenInfo.value)
	const str = isHuff ? huffman.decode(raw).toString('utf8') : raw.toString('utf8')
	return { value: str, length: lenInfo.length + lenInfo.value }
}

// Helpers for the encoder.
function findInTables(name, value, table) {
	for (let i = 1; i <= STATIC_LEN; i++) {
		const [n, v] = STATIC[i]
		if (n === name && v === value) return { exact: i }
	}
	for (let i = 0; i < table.entries.length; i++) {
		const [n, v] = table.entries[i]
		if (n === name && v === value) return { exact: STATIC_LEN + 1 + i }
	}
	// Name-only fallback (prefer static for stability)
	for (let i = 1; i <= STATIC_LEN; i++) if (STATIC[i][0] === name) return { nameOnly: i }
	for (let i = 0; i < table.entries.length; i++) if (table.entries[i][0] === name) return { nameOnly: STATIC_LEN + 1 + i }
	return null
}

// Encode a list of [name, value] pairs. We use Literal Without Indexing for non-indexed
// values — stateless encoder, no dynamic table writes from our side. Matches what Node's
// http2 does by default for non-sensitive headers.
function encode(headers, table) {
	const out = []
	for (const [name, value] of headers) {
		const n = String(name).toLowerCase()
		const v = String(value)
		const m = findInTables(n, v, table)
		if (m && m.exact != null) {
			out.push(encodeInt(m.exact, 7, 0x80))
		} else if (m && m.nameOnly != null) {
			out.push(encodeInt(m.nameOnly, 4, 0x00))   // Without Indexing, name index
			out.push(encodeString(v))
		} else {
			out.push(Buffer.from([0x00]))               // Without Indexing, literal name
			out.push(encodeString(n))
			out.push(encodeString(v))
		}
	}
	return Buffer.concat(out)
}

// Decode an HPACK-encoded header block against the (caller-managed) dynamic table.
function decode(buf, table) {
	const headers = []
	let o = 0
	while (o < buf.length) {
		const b = buf[o]
		if ((b & 0x80) === 0x80) {
			// Indexed Header Field
			const idx = decodeInt(buf, o, 7); o += idx.length
			const e = table.lookup(idx.value)
			if (e) headers.push([e[0], e[1]])
			continue
		}
		if ((b & 0xc0) === 0x40) {
			// Literal With Incremental Indexing
			const idx = decodeInt(buf, o, 6); o += idx.length
			let name
			if (idx.value === 0) {
				const nameStr = decodeString(buf, o); o += nameStr.length
				name = nameStr.value
			} else {
				const e = table.lookup(idx.value)
				name = e ? e[0] : ''
			}
			const valStr = decodeString(buf, o); o += valStr.length
			headers.push([name, valStr.value])
			table.add(name, valStr.value)
			continue
		}
		if ((b & 0xe0) === 0x20) {
			// Dynamic Table Size Update
			const sz = decodeInt(buf, o, 5); o += sz.length
			table.setCapacity(sz.value)
			continue
		}
		// Literal Without / Never Indexing: 0000xxxx or 0001xxxx — both 4-bit name index.
		if ((b & 0xf0) === 0x00 || (b & 0xf0) === 0x10) {
			const idx = decodeInt(buf, o, 4); o += idx.length
			let name
			if (idx.value === 0) {
				const nameStr = decodeString(buf, o); o += nameStr.length
				name = nameStr.value
			} else {
				const e = table.lookup(idx.value)
				name = e ? e[0] : ''
			}
			const valStr = decodeString(buf, o); o += valStr.length
			headers.push([name, valStr.value])
			continue
		}
		// Unknown — bail
		break
	}
	return headers
}

module.exports = { STATIC, STATIC_LEN, DynamicTable, encode, decode, encodeInt, decodeInt }
