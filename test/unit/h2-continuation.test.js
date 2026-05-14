// h2 CONTINUATION frame send/receive when header blocks exceed MAX_FRAME_SIZE.

const test = require('node:test')
const assert = require('node:assert')
const { H2Session } = require('../../lib/h2/session')
const frame = require('../../lib/h2/frame')
const { Duplex } = require('node:stream')

function mockTransport() {
	const written = []
	const t = new Duplex({
		write(chunk, _enc, cb) { written.push(Buffer.from(chunk)); cb() },
		read() {},
	})
	t.written = written
	return t
}

test('huge header block is sent as HEADERS + CONTINUATION(s)', () => {
	const t = mockTransport()
	const s = new H2Session(t)

	// 40KB cookie ensures the encoded header block exceeds 16KB MAX_FRAME_SIZE.
	const giant = 'x'.repeat(40_000)
	s.request({ ':method': 'GET', ':scheme': 'https', ':authority': 'a', ':path': '/', cookie: giant })

	// Drop preface (24) + SETTINGS + WINDOW_UPDATE, then look at remaining frames.
	const all = Buffer.concat(t.written)
	let off = 24
	const frames = []
	while (off < all.length) {
		const f = frame.parse(all.subarray(off))
		if (!f) break
		frames.push(f)
		off += f.consumed
	}
	const headerFrames = frames.filter(f => f.type === frame.TYPE.HEADERS)
	const contFrames   = frames.filter(f => f.type === frame.TYPE.CONTINUATION)
	assert.strictEqual(headerFrames.length, 1, 'exactly one HEADERS frame')
	assert.ok(contFrames.length >= 1, `expected CONTINUATION frames, got ${contFrames.length}`)

	// HEADERS must NOT carry END_HEADERS (the last CONT does).
	assert.strictEqual(headerFrames[0].flags & frame.FLAG.END_HEADERS, 0)
	// The LAST CONT must carry END_HEADERS.
	const last = contFrames[contFrames.length - 1]
	assert.strictEqual(last.flags & frame.FLAG.END_HEADERS, frame.FLAG.END_HEADERS)
	// Non-last CONTs do not.
	for (let i = 0; i < contFrames.length - 1; i++) {
		assert.strictEqual(contFrames[i].flags & frame.FLAG.END_HEADERS, 0)
	}
})

test('inbound: HEADERS+CONTINUATION reassembles into a single response event', async () => {
	const t = mockTransport()
	const s = new H2Session(t)
	// Drive a request so we have a registered stream
	const stream = s.request({ ':method': 'GET', ':scheme': 'https', ':authority': 'a', ':path': '/' })

	// Encode a big response header block and split it across one HEADERS + one CONTINUATION.
	const hpack = require('../../lib/h2/hpack')
	const responsePairs = [
		[':status', '200'],
		['content-type', 'application/json'],
		['x-huge', 'y'.repeat(40_000)],
	]
	const encoded = hpack.encode(responsePairs, s.peerHpackTable)
	const mid = Math.floor(encoded.length / 2)
	const firstBlock = encoded.subarray(0, mid)
	const restBlock  = encoded.subarray(mid)

	let gotResponse = null
	stream.once('response', (h) => { gotResponse = h })

	// Inbound HEADERS (no END_HEADERS) + CONTINUATION (END_HEADERS)
	const streamId = 1   // first client stream
	const headersFrame = frame.build(frame.TYPE.HEADERS, 0, streamId, firstBlock)
	const contFrame    = frame.build(frame.TYPE.CONTINUATION, frame.FLAG.END_HEADERS, streamId, restBlock)
	t.push(headersFrame)
	t.push(contFrame)

	await new Promise((r) => setImmediate(r))
	assert.ok(gotResponse, 'response event fired after END_HEADERS arrived')
	assert.strictEqual(gotResponse[':status'], '200')
	assert.strictEqual(gotResponse['x-huge']?.length, 40_000)
})
