const huffman = require('./huffman')

// QPACK encoder, static-only (RFC 9204).
//
// We only emit "Literal Field Line With Name Reference" (using the static table) and
// "Literal Field Line With Literal Name" forms — never use the dynamic table. This
// significantly limits header compression but avoids the encoder/decoder stream
// machinery. Cloudflare and other major servers accept this (decoder side just
// ignores the absence of dynamic-table updates).
//
// QPACK requires every HEADERS frame body to start with two field-section-prefix
// values (Required Insert Count + Delta Base), both encoded as QPACK integers. We
// always emit (0, 0) which means "no dynamic table dependency, base = 0".

// Static table (RFC 9204 Appendix A) — abbreviated to entries we actually emit.
const STATIC_TABLE = [
	[':authority', ''],
	[':path', '/'],
	['age', '0'],
	['content-disposition', ''],
	['content-length', '0'],
	['cookie', ''],
	['date', ''],
	['etag', ''],
	['if-modified-since', ''],
	['if-none-match', ''],
	['last-modified', ''],
	['link', ''],
	['location', ''],
	['referer', ''],
	['set-cookie', ''],
	[':method', 'CONNECT'],
	[':method', 'DELETE'],
	[':method', 'GET'],
	[':method', 'HEAD'],
	[':method', 'OPTIONS'],
	[':method', 'POST'],
	[':method', 'PUT'],
	[':scheme', 'http'],
	[':scheme', 'https'],
	[':status', '103'],
	[':status', '200'],
	[':status', '304'],
	[':status', '404'],
	[':status', '503'],
	['accept', '*/*'],
	['accept', 'application/dns-message'],
	['accept-encoding', 'gzip, deflate, br'],
	['accept-ranges', 'bytes'],
	['access-control-allow-headers', 'cache-control'],
	['access-control-allow-headers', 'content-type'],
	['access-control-allow-origin', '*'],
	['cache-control', 'max-age=0'],
	['cache-control', 'max-age=2592000'],
	['cache-control', 'max-age=604800'],
	['cache-control', 'no-cache'],
	['cache-control', 'no-store'],
	['cache-control', 'public, max-age=31536000'],
	['content-encoding', 'br'],
	['content-encoding', 'gzip'],
	['content-type', 'application/dns-message'],
	['content-type', 'application/javascript'],
	['content-type', 'application/json'],
	['content-type', 'application/x-www-form-urlencoded'],
	['content-type', 'image/gif'],
	['content-type', 'image/jpeg'],
	['content-type', 'image/png'],
	['content-type', 'text/css'],
	['content-type', 'text/html; charset=utf-8'],
	['content-type', 'text/plain'],
	['content-type', 'text/plain;charset=utf-8'],
	['range', 'bytes=0-'],
	['strict-transport-security', 'max-age=31536000'],
	['strict-transport-security', 'max-age=31536000; includesubdomains'],
	['strict-transport-security', 'max-age=31536000; includesubdomains; preload'],
	['vary', 'accept-encoding'],
	['vary', 'origin'],
	['x-content-type-options', 'nosniff'],
	['x-xss-protection', '1; mode=block'],
	[':status', '100'],
	[':status', '204'],
	[':status', '206'],
	[':status', '302'],
	[':status', '400'],
	[':status', '403'],
	[':status', '421'],
	[':status', '425'],
	[':status', '500'],
	['accept-language', ''],
	['access-control-allow-credentials', 'FALSE'],
	['access-control-allow-credentials', 'TRUE'],
	['access-control-allow-headers', '*'],
	['access-control-allow-methods', 'get'],
	['access-control-allow-methods', 'get, post, options'],
	['access-control-allow-methods', 'options'],
	['access-control-expose-headers', 'content-length'],
	['access-control-request-headers', 'content-type'],
	['access-control-request-method', 'get'],
	['access-control-request-method', 'post'],
	['alt-svc', 'clear'],
	['authorization', ''],
	['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"],
	['early-data', '1'],
	['expect-ct', ''],
	['forwarded', ''],
	['if-range', ''],
	['origin', ''],
	['purpose', 'prefetch'],
	['server', ''],
	['timing-allow-origin', '*'],
	['upgrade-insecure-requests', '1'],
	['user-agent', ''],
	['x-forwarded-for', ''],
	['x-frame-options', 'deny'],
	['x-frame-options', 'sameorigin'],
]

// Find the static-table index for (name, value) — exact match first, then name-only.
function findStatic(name, value) {
	let nameIdx = -1
	for (let i = 0; i < STATIC_TABLE.length; i++) {
		const [n, v] = STATIC_TABLE[i]
		if (n === name) {
			if (v === value) return { exact: i }
			if (nameIdx < 0) nameIdx = i
		}
	}
	return nameIdx >= 0 ? { nameOnly: nameIdx } : null
}

// QPACK integer encoding (RFC 9204 §4.1.1) — N-bit prefix on first byte.
function encodeInt(value, prefixBits, firstBytePrefix) {
	const max = (1 << prefixBits) - 1
	if (value < max) return Buffer.from([firstBytePrefix | value])
	const out = [firstBytePrefix | max]
	value -= max
	while (value >= 128) { out.push((value & 0x7f) | 0x80); value = value >>> 7 }
	out.push(value)
	return Buffer.from(out)
}

// String literal: 1-bit huffman flag (we always 0 = no huffman) + 7-bit length + bytes.
function encodeString(str) {
	const b = Buffer.from(str, 'utf8')
	return Buffer.concat([encodeInt(b.length, 7, 0x00), b])
}

// Encode a headers list (array of [name, value]) into a QPACK encoded field section.
function encodeHeaders(headers) {
	const out = []
	// Field section prefix: Required Insert Count = 0 (encoded as 0), Delta Base = 0 (encoded as sign=0, value=0).
	out.push(encodeInt(0, 8, 0x00))   // Required Insert Count
	out.push(encodeInt(0, 7, 0x00))   // Delta Base (S=0, base=0)
	for (const [n, v] of headers) {
		const m = findStatic(n.toLowerCase(), v)
		if (m && typeof m.exact === 'number') {
			// Indexed Field Line — 1Txxxxxx, T=1 (static)
			out.push(encodeInt(m.exact, 6, 0xc0))
		} else if (m && typeof m.nameOnly === 'number') {
			// Literal Field Line With Name Reference — 01NTxxxx; we set N=0, T=1 (static)
			out.push(encodeInt(m.nameOnly, 4, 0x50))
			out.push(encodeString(v))
		} else {
			// Literal Field Line With Literal Name — 001NHxxx; H = huffman bit (0)
			out.push(encodeInt(n.length, 3, 0x20))
			out.push(Buffer.from(n.toLowerCase(), 'utf8'))
			out.push(encodeString(v))
		}
	}
	return Buffer.concat(out)
}

// Decode a QPACK integer.
function decodeInt(buf, offset, prefixBits) {
	const max = (1 << prefixBits) - 1
	let v = buf[offset] & max
	let off = offset + 1
	if (v < max) return { value: v, length: off - offset }
	let m = 0
	while (true) {
		const b = buf[off++]
		v += (b & 0x7f) << m
		m += 7
		if ((b & 0x80) === 0) break
	}
	return { value: v, length: off - offset }
}

// Decode QPACK encoded field section. Returns array of [name, value] tuples. We support a subset matching what we encode (no huffman, no dynamic table).
function decodeHeaders(buf) {
	let off = 0
	const required = decodeInt(buf, off, 8); off += required.length
	const baseFirstByte = buf[off]
	const baseSign = (baseFirstByte & 0x80) !== 0
	const base = decodeInt(buf, off, 7); off += base.length
	const headers = []
	while (off < buf.length) {
		const b = buf[off]
		if ((b & 0xc0) === 0xc0) {
			// Indexed Field Line: 1T______, T=1 static.
			const t = (b & 0x40) !== 0
			const idx = decodeInt(buf, off, 6); off += idx.length
			const e = STATIC_TABLE[idx.value]
			if (!e) { off = buf.length; break }
			headers.push([e[0], e[1]])
			continue
		}
		if ((b & 0xf0) === 0x50 || (b & 0xf0) === 0x40) {
			// Literal With Name Reference: 01NT____ ; T=static; bit at 0x10 doesn't matter for static index here
			const idx = decodeInt(buf, off, 4); off += idx.length
			const e = STATIC_TABLE[idx.value]
			const huff = (buf[off] & 0x80) !== 0
			const len = decodeInt(buf, off, 7); off += len.length
			const raw = buf.subarray(off, off + len.value); off += len.value
			const val = huff ? huffman.decode(raw).toString('utf8') : raw.toString('utf8')
			if (!e) continue
			headers.push([e[0], val])
			continue
		}
		if ((b & 0xe0) === 0x20) {
			// Literal With Literal Name: 001NH___ where H is at bit 0x08
			const nameHuff = (b & 0x08) !== 0
			const nlen = decodeInt(buf, off, 3); off += nlen.length
			const nameRaw = buf.subarray(off, off + nlen.value); off += nlen.value
			const name = nameHuff ? huffman.decode(nameRaw).toString('utf8') : nameRaw.toString('utf8')
			const valHuff = (buf[off] & 0x80) !== 0
			const vlen = decodeInt(buf, off, 7); off += vlen.length
			const valRaw = buf.subarray(off, off + vlen.value); off += vlen.value
			const val = valHuff ? huffman.decode(valRaw).toString('utf8') : valRaw.toString('utf8')
			headers.push([name, val])
			continue
		}
		if ((b & 0xf0) === 0x10) {
			// Indexed Field Line With Post-Base Index — not supported, skip
			off++
			continue
		}
		// Unknown — bail
		break
	}
	return headers
}

// Dynamic table (RFC 9204 §3.2). Maintained per-connection as a FIFO with a byte-size
// budget. Each entry costs name.length + value.length + 32 bytes (RFC 7541 §4.1).
class DynamicTable {
	constructor() {
		this.entries = []          // newest at end; indices grow over time (absolute)
		this.totalInserted = 0     // monotonic counter
		this.capacity = 0          // bytes; set by Set Dynamic Table Capacity instruction
		this.size = 0              // current byte usage
	}

	// Look up by absolute (post-base) index — counted from the oldest still-resident entry.
	getAbsolute(absIdx) {
		const oldestAbs = this.totalInserted - this.entries.length
		const i = absIdx - oldestAbs
		return this.entries[i] || null
	}

	// Look up by relative index (relative to base) — 0 = newest, growing into the past.
	getRelative(base, idx) {
		const absIdx = base - idx - 1
		return this.getAbsolute(absIdx)
	}

	getPostBase(base, idx) {
		return this.getAbsolute(base + idx)
	}

	insert(name, value) {
		const cost = name.length + value.length + 32
		this.entries.push([name, value])
		this.size += cost
		this.totalInserted++
		while (this.size > this.capacity && this.entries.length > 0) {
			const [n, v] = this.entries.shift()
			this.size -= n.length + v.length + 32
		}
	}

	setCapacity(cap) {
		this.capacity = cap
		while (this.size > this.capacity && this.entries.length > 0) {
			const [n, v] = this.entries.shift()
			this.size -= n.length + v.length + 32
		}
	}
}

// Decode a string literal at offset: 1-bit huffman flag + prefixBits length + bytes.
// (prefixBits varies by context: 7 for "value" literal, 5 for encoder-stream name literal.)
function decodeLiteralString(buf, off, prefixBits) {
	const isHuff = (buf[off] & (1 << prefixBits)) !== 0
	const len = decodeInt(buf, off, prefixBits)
	off += len.length
	const raw = buf.subarray(off, off + len.value)
	const str = isHuff ? huffman.decode(raw).toString('utf8') : raw.toString('utf8')
	return { value: str, length: (len.length + len.value) }
}

// Parse incoming encoder-stream instructions and update the dynamic table.
// Returns the new offset (so the caller can preserve any trailing partial instruction
// for the next call). Per RFC 9204 §4.3.
function parseEncoderInstructions(buf, table) {
	let off = 0
	while (off < buf.length) {
		const b = buf[off]
		// Set Dynamic Table Capacity — 001xxxxx, 5-bit value
		if ((b & 0xe0) === 0x20) {
			const cap = decodeInt(buf, off, 5)
			off += cap.length
			table.setCapacity(cap.value)
			continue
		}
		// Insert With Name Reference — 1Txxxxxx, T=1 static, T=0 dynamic, 6-bit index
		if ((b & 0x80) === 0x80) {
			const t = (b & 0x40) !== 0
			const idx = decodeInt(buf, off, 6)
			const after = off + idx.length
			if (after >= buf.length) return off  // need more bytes for value
			const val = decodeLiteralString(buf, after, 7)
			const total = idx.length + val.length
			let name
			if (t) {
				const e = STATIC_TABLE[idx.value]
				if (!e) { off += total; continue }
				name = e[0]
			} else {
				const e = table.getRelative(table.totalInserted, idx.value)
				if (!e) { off += total; continue }
				name = e[0]
			}
			table.insert(name, val.value)
			off += total
			continue
		}
		// Insert With Literal Name — 01Hxxxxxx, H=name-huffman, 5-bit name length
		if ((b & 0xc0) === 0x40) {
			const nameInfo = decodeLiteralString(buf, off, 5)
			const valInfo = decodeLiteralString(buf, off + nameInfo.length, 7)
			table.insert(nameInfo.value, valInfo.value)
			off += nameInfo.length + valInfo.length
			continue
		}
		// Duplicate — 000xxxxx, 5-bit relative index
		if ((b & 0xe0) === 0x00) {
			const idx = decodeInt(buf, off, 5)
			off += idx.length
			const e = table.getRelative(table.totalInserted, idx.value)
			if (e) table.insert(e[0], e[1])
			continue
		}
		// Unknown instruction — bail to preserve byte stream
		return off
	}
	return off
}

// Decode the field section prefix's encoded Required Insert Count back into the actual
// insertion count required to decode the section (RFC 9204 §4.5.1.1).
function decodeRequiredInsertCount(encodedRic, totalInserted, maxEntries) {
	if (encodedRic === 0) return 0
	const fullRange = 2 * maxEntries
	const maxValue = totalInserted + maxEntries
	const maxWrapped = Math.floor(maxValue / fullRange) * fullRange
	let ric = maxWrapped + encodedRic - 1
	if (ric > maxValue) {
		if (ric < fullRange) throw new Error('QPACK: invalid Required Insert Count (would underflow)')
		ric -= fullRange
	}
	return ric
}

// Replace the static-only decodeHeaders with a dynamic-table-aware version.
// Pass `table` (DynamicTable) and `maxEntries` (capacity / 32) to allow dynamic refs.
function decodeHeadersWithTable(buf, table = null, maxEntries = 0) {
	let off = 0
	const ricInfo = decodeInt(buf, off, 8); off += ricInfo.length
	const baseFirstByte = buf[off]
	const baseSign = (baseFirstByte & 0x80) !== 0
	const baseInfo = decodeInt(buf, off, 7); off += baseInfo.length

	const ric = (table && maxEntries > 0) ? decodeRequiredInsertCount(ricInfo.value, table.totalInserted, maxEntries) : 0
	const base = baseSign ? ric - baseInfo.value - 1 : ric + baseInfo.value

	const headers = []
	while (off < buf.length) {
		const b = buf[off]
		// Indexed Field Line: 1Txxxxxx — top bit is the type tag, bit 0x40 is T.
		if ((b & 0x80) === 0x80) {
			const t = (b & 0x40) !== 0
			const idx = decodeInt(buf, off, 6); off += idx.length
			let e
			if (t) e = STATIC_TABLE[idx.value]
			else if (table) e = table.getRelative(base, idx.value)
			if (e) headers.push([e[0], e[1]])
			continue
		}
		// Indexed Field Line With Post-Base Index: 0001xxxx
		if ((b & 0xf0) === 0x10) {
			const idx = decodeInt(buf, off, 4); off += idx.length
			if (table) {
				const e = table.getPostBase(base, idx.value)
				if (e) headers.push([e[0], e[1]])
			}
			continue
		}
		// Literal Field Line With Name Reference: 01NTxxxx
		if ((b & 0xc0) === 0x40) {
			const t = (b & 0x10) !== 0
			const idx = decodeInt(buf, off, 4); off += idx.length
			let nameRef
			if (t) nameRef = STATIC_TABLE[idx.value]?.[0]
			else nameRef = table?.getRelative(base, idx.value)?.[0]
			const valInfo = decodeLiteralString(buf, off, 7); off += valInfo.length
			if (nameRef != null) headers.push([nameRef, valInfo.value])
			continue
		}
		// Literal Field Line With Post-Base Name Reference: 0000xxxx
		if ((b & 0xf0) === 0x00) {
			const idx = decodeInt(buf, off, 3); off += idx.length
			const nameRef = table?.getPostBase(base, idx.value)?.[0]
			const valInfo = decodeLiteralString(buf, off, 7); off += valInfo.length
			if (nameRef != null) headers.push([nameRef, valInfo.value])
			continue
		}
		// Literal Field Line With Literal Name: 001NHxxx
		if ((b & 0xe0) === 0x20) {
			const nameInfo = decodeLiteralString(buf, off, 3); off += nameInfo.length
			const valInfo = decodeLiteralString(buf, off, 7); off += valInfo.length
			headers.push([nameInfo.value, valInfo.value])
			continue
		}
		break
	}
	return headers
}

module.exports = {
	STATIC_TABLE,
	findStatic,
	encodeInt,
	encodeString,
	encodeHeaders,
	decodeInt,
	decodeHeaders,
	// Dynamic-table additions
	DynamicTable,
	parseEncoderInstructions,
	decodeHeadersWithTable,
}
