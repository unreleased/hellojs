// QUIC variable-length integer codec (RFC 9000 §16).
//
// First two bits of the first byte encode the length:
//   0b00 → 1 byte (6-bit value, 0..63)
//   0b01 → 2 bytes (14-bit value, 0..16383)
//   0b10 → 4 bytes (30-bit value, 0..2^30-1)
//   0b11 → 8 bytes (62-bit value, 0..2^62-1)
// The length-prefix bits are the MSBs of the first byte.

function encode(value) {
	const v = BigInt(value)
	if (v < 0n) throw new Error('varint: negative')
	if (v < 64n) {
		return Buffer.from([Number(v)])
	}
	if (v < 16384n) {
		const b = Buffer.alloc(2)
		b.writeUInt16BE(Number(v) | 0x4000, 0)
		return b
	}
	if (v < (1n << 30n)) {
		const b = Buffer.alloc(4)
		b.writeUInt32BE((Number(v) | 0x80000000) >>> 0, 0)
		return b
	}
	if (v < (1n << 62n)) {
		const b = Buffer.alloc(8)
		b.writeBigUInt64BE(v | 0xc000000000000000n, 0)
		return b
	}
	throw new Error('varint: value too large')
}

function decode(buf, offset = 0) {
	if (offset >= buf.length) throw new Error('varint: short buffer')
	const first = buf[offset]
	const prefix = first >> 6
	const len = 1 << prefix
	if (offset + len > buf.length) throw new Error('varint: truncated')
	let value
	if (len === 1) {
		value = first & 0x3f
	} else if (len === 2) {
		value = ((first & 0x3f) << 8) | buf[offset + 1]
	} else if (len === 4) {
		value = ((first & 0x3f) << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]
	} else {
		// 8 bytes — use BigInt then narrow
		const big = (BigInt(first & 0x3f) << 56n) |
			(BigInt(buf[offset + 1]) << 48n) |
			(BigInt(buf[offset + 2]) << 40n) |
			(BigInt(buf[offset + 3]) << 32n) |
			(BigInt(buf[offset + 4]) << 24n) |
			(BigInt(buf[offset + 5]) << 16n) |
			(BigInt(buf[offset + 6]) << 8n) |
			BigInt(buf[offset + 7])
		value = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big
	}
	return { value, length: len }
}

// Encode a fixed-length big-endian uint with the supplied byte count (used for QUIC packet numbers, which are NOT varints; they're 1-4 byte fixed BE).
function encodeUint(value, byteLen) {
	const b = Buffer.alloc(byteLen)
	for (let i = byteLen - 1; i >= 0; i--) { b[i] = value & 0xff; value >>>= 8 }
	return b
}

function decodeUint(buf, offset, byteLen) {
	let v = 0
	for (let i = 0; i < byteLen; i++) v = (v << 8) | buf[offset + i]
	return v >>> 0
}

module.exports = { encode, decode, encodeUint, decodeUint }
