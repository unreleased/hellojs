// h2 frame codec — 9-byte header + payload.

const test = require('node:test')
const assert = require('node:assert')
const frame = require('../../lib/h2/frame')

test('build + parse round-trip preserves type/flags/streamId/payload', () => {
	const payload = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05])
	const built = frame.build(frame.TYPE.DATA, frame.FLAG.END_STREAM, 7, payload)
	const parsed = frame.parse(built)
	assert.strictEqual(parsed.type, frame.TYPE.DATA)
	assert.strictEqual(parsed.flags, frame.FLAG.END_STREAM)
	assert.strictEqual(parsed.streamId, 7)
	assert.strictEqual(parsed.length, payload.length)
	assert.deepStrictEqual(Buffer.from(parsed.payload), payload)
	assert.strictEqual(parsed.consumed, built.length)
})

test('parse returns null for an incomplete header (< 9 bytes)', () => {
	assert.strictEqual(frame.parse(Buffer.from([0])), null)
	assert.strictEqual(frame.parse(Buffer.alloc(8)), null)
})

test('parse returns null when payload is incomplete', () => {
	// Header claims 100-byte payload, supply only 10
	const incomplete = Buffer.alloc(9 + 10)
	incomplete.writeUIntBE(100, 0, 3)
	assert.strictEqual(frame.parse(incomplete), null)
})

test('SETTINGS round-trip preserves id/value pairs', () => {
	const pairs = [
		[frame.SETTING.HEADER_TABLE_SIZE, 65536],
		[frame.SETTING.ENABLE_PUSH, 0],
		[frame.SETTING.MAX_HEADER_LIST_SIZE, 262144],
	]
	const built = frame.buildSettings(pairs)
	const parsed = frame.parseSettings(built)
	assert.deepStrictEqual(parsed, pairs)
})

test('stream id top bit is always cleared (reserved bit)', () => {
	const built = frame.build(frame.TYPE.HEADERS, 0, 0xffffffff, Buffer.alloc(0))
	const parsed = frame.parse(built)
	assert.strictEqual(parsed.streamId, 0x7fffffff)
})

test('WINDOW_UPDATE payload encodes increment as u32', () => {
	const p = frame.buildWindowUpdate(15663105)
	assert.strictEqual(p.length, 4)
	assert.strictEqual(p.readUInt32BE(0), 15663105)
})

test('GOAWAY round-trip preserves lastStreamId + errorCode + debugData', () => {
	const debug = Buffer.from('something went wrong', 'utf8')
	const p = frame.buildGoaway(42, frame.ERROR.PROTOCOL_ERROR, debug)
	const parsed = frame.parseGoaway(p)
	assert.strictEqual(parsed.lastStreamId, 42)
	assert.strictEqual(parsed.errorCode, frame.ERROR.PROTOCOL_ERROR)
	assert.deepStrictEqual(Buffer.from(parsed.debugData), debug)
})
