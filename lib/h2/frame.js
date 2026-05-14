// HTTP/2 frame codec (RFC 7540 §4, §6).
//
// Every frame is a 9-byte fixed header:
//   24 bits   length (payload only)
//    8 bits   type
//    8 bits   flags
//    1 bit    reserved
//   31 bits   stream id
// ...followed by `length` bytes of type-specific payload.

const TYPE = {
	DATA:          0x00,
	HEADERS:       0x01,
	PRIORITY:      0x02,
	RST_STREAM:    0x03,
	SETTINGS:      0x04,
	PUSH_PROMISE:  0x05,
	PING:          0x06,
	GOAWAY:        0x07,
	WINDOW_UPDATE: 0x08,
	CONTINUATION:  0x09,
}

const FLAG = {
	END_STREAM:  0x01,
	ACK:         0x01,
	END_HEADERS: 0x04,
	PADDED:      0x08,
	PRIORITY:    0x20,
}

const ERROR = {
	NO_ERROR:            0x00,
	PROTOCOL_ERROR:      0x01,
	INTERNAL_ERROR:      0x02,
	FLOW_CONTROL_ERROR:  0x03,
	SETTINGS_TIMEOUT:    0x04,
	STREAM_CLOSED:       0x05,
	FRAME_SIZE_ERROR:    0x06,
	REFUSED_STREAM:      0x07,
	CANCEL:              0x08,
	COMPRESSION_ERROR:   0x09,
	CONNECT_ERROR:       0x0a,
	ENHANCE_YOUR_CALM:   0x0b,
	INADEQUATE_SECURITY: 0x0c,
	HTTP_1_1_REQUIRED:   0x0d,
}

const SETTING = {
	HEADER_TABLE_SIZE:      0x01,
	ENABLE_PUSH:            0x02,
	MAX_CONCURRENT_STREAMS: 0x03,
	INITIAL_WINDOW_SIZE:    0x04,
	MAX_FRAME_SIZE:         0x05,
	MAX_HEADER_LIST_SIZE:   0x06,
	// RFC 9218 — used by Safari to disable RFC 7540 priority signaling in favor of
	// HTTP extensible priorities. Wire value is 1 to disable.
	NO_RFC7540_PRIORITIES:  0x09,
}

// Build a frame: returns Buffer with the 9-byte header + payload.
function build(type, flags, streamId, payload) {
	const hdr = Buffer.alloc(9)
	hdr.writeUIntBE(payload.length, 0, 3)
	hdr[3] = type
	hdr[4] = flags
	hdr.writeUInt32BE(streamId & 0x7fffffff, 5)
	return payload.length ? Buffer.concat([hdr, payload]) : hdr
}

// Try to parse one frame from the start of `buf`. Returns { length, type, flags,
// streamId, payload, consumed } or null if `buf` doesn't yet contain a full frame.
function parse(buf) {
	if (buf.length < 9) return null
	const length = buf.readUIntBE(0, 3)
	if (buf.length < 9 + length) return null
	const type = buf[3]
	const flags = buf[4]
	const streamId = buf.readUInt32BE(5) & 0x7fffffff
	const payload = buf.subarray(9, 9 + length)
	return { length, type, flags, streamId, payload, consumed: 9 + length }
}

// SETTINGS payload is a sequence of (u16 id, u32 value) pairs.
function buildSettings(pairs) {
	const buf = Buffer.alloc(6 * pairs.length)
	let o = 0
	for (const [id, v] of pairs) {
		buf.writeUInt16BE(id, o); o += 2
		buf.writeUInt32BE(v >>> 0, o); o += 4
	}
	return buf
}

function parseSettings(payload) {
	const out = []
	for (let o = 0; o + 6 <= payload.length; o += 6) {
		out.push([payload.readUInt16BE(o), payload.readUInt32BE(o + 2)])
	}
	return out
}

function buildWindowUpdate(increment) {
	const p = Buffer.alloc(4)
	p.writeUInt32BE(increment >>> 0, 0)
	return p
}

function buildRstStream(errorCode) {
	const p = Buffer.alloc(4)
	p.writeUInt32BE(errorCode >>> 0, 0)
	return p
}

function buildGoaway(lastStreamId, errorCode, debugData = Buffer.alloc(0)) {
	const p = Buffer.alloc(8 + debugData.length)
	p.writeUInt32BE(lastStreamId & 0x7fffffff, 0)
	p.writeUInt32BE(errorCode >>> 0, 4)
	debugData.copy(p, 8)
	return p
}

function parseGoaway(payload) {
	return {
		lastStreamId: payload.readUInt32BE(0) & 0x7fffffff,
		errorCode: payload.readUInt32BE(4),
		debugData: payload.subarray(8),
	}
}

module.exports = {
	TYPE, FLAG, ERROR, SETTING,
	build, parse,
	buildSettings, parseSettings,
	buildWindowUpdate, buildRstStream,
	buildGoaway, parseGoaway,
}
