// H2Stream write/end streaming interface — verified against a mock session.

const test = require('node:test')
const assert = require('node:assert')
const { H2Session } = require('../../lib/h2/session')
const frame = require('../../lib/h2/frame')
const { Duplex, Readable } = require('node:stream')

function mockTransport() {
	const written = []
	const t = new Duplex({
		write(chunk, _enc, cb) { written.push(Buffer.from(chunk)); cb() },
		read() {},
	})
	t.written = written
	return t
}

test('H2Stream.write sends DATA without END_STREAM, end() sends final DATA with END_STREAM', () => {
	const t = mockTransport()
	const s = new H2Session(t)
	const stream = s.request({ ':method': 'POST', ':scheme': 'https', ':authority': 'a', ':path': '/' })

	stream.write(Buffer.from('hello '))
	stream.write(Buffer.from('world'))
	stream.end()

	// Frames in t.written: H2 preface + SETTINGS + WINDOW_UPDATE + HEADERS + DATA + DATA + DATA(end)
	const all = Buffer.concat(t.written)
	// Skip the 24-byte preface + everything else; just decode all frames after the preface.
	const PREFACE_LEN = 24
	let off = PREFACE_LEN
	const frames = []
	while (off < all.length) {
		const f = frame.parse(all.subarray(off))
		if (!f) break
		frames.push(f)
		off += f.consumed
	}
	const dataFrames = frames.filter(f => f.type === frame.TYPE.DATA)
	// 'hello ' (no end), 'world' (no end), empty (end)
	assert.strictEqual(dataFrames.length, 3, 'expected 3 DATA frames')
	assert.strictEqual(dataFrames[0].flags & frame.FLAG.END_STREAM, 0)
	assert.strictEqual(dataFrames[1].flags & frame.FLAG.END_STREAM, 0)
	assert.strictEqual(dataFrames[2].flags & frame.FLAG.END_STREAM, frame.FLAG.END_STREAM)
	assert.strictEqual(dataFrames[2].length, 0)
})

test('Streaming body: Readable detected as object with pipe()', () => {
	const r = Readable.from(['a', 'b', 'c'])
	assert.strictEqual(typeof r.pipe, 'function')
})
