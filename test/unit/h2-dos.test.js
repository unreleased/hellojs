// Tier-2 remote-DoS hardening for HTTP/2: malformed HPACK / oversized header blocks from the peer
// must fail the request and tear down the connection, not crash the process or exhaust memory.

const test = require('node:test')
const assert = require('node:assert')
const { EventEmitter } = require('node:events')
const { H2Session } = require('../../lib/h2/session')
const hpack = require('../../lib/h2/hpack')
const frame = require('../../lib/h2/frame')

const REQ = { ':method': 'GET', ':path': '/', ':scheme': 'https', ':authority': 'x' }

// A transport that discards writes (a PassThrough would loop the session's own output back into
// its reader and desync the parser). We drive inbound bytes via session._onData directly.
function fakeTransport() {
	const t = new EventEmitter()
	t.write = () => true
	t.destroy = () => {}
	return t
}

test('hpack.decode caps decoded header-list size (decompression bomb)', () => {
	// 7000 indexed references to a static entry decode to ~294 KB, over the 256 KB cap.
	assert.throws(() => hpack.decode(Buffer.alloc(7000, 0x82), new hpack.DynamicTable()), /MAX_HEADER_LIST_SIZE/)
	// A small, legitimate block still decodes fine.
	assert.doesNotThrow(() => hpack.decode(Buffer.from([0x82, 0x84]), new hpack.DynamicTable()))
})

test('oversized HPACK on a stream fails the request instead of crashing', () => {
	const session = new H2Session(fakeTransport())
	const stream = session.request(REQ)
	let err = null, closed = false
	stream.on('error', (e) => { err = e })
	session.on('close', () => { closed = true })
	// Response HEADERS for stream 1 carrying a decompression-bomb HPACK block.
	assert.doesNotThrow(() => session._onData(frame.build(frame.TYPE.HEADERS, frame.FLAG.END_HEADERS, 1, Buffer.alloc(7000, 0x82))))
	assert.ok(err && /h2 connection error/.test(err.message), `stream should receive a connection error, got ${err && err.message}`)
	assert.strictEqual(err.code, 'EH2COMPRESS')
	assert.ok(closed, 'session should emit close so the pool evicts it')
})

test('CONTINUATION flood is bounded (no unbounded fragment growth)', () => {
	const session = new H2Session(fakeTransport())
	const stream = session.request(REQ)
	let err = null
	stream.on('error', (e) => { err = e })
	// HEADERS without END_HEADERS, then CONTINUATION frames totalling > 256 KB.
	session._onData(frame.build(frame.TYPE.HEADERS, 0, 1, Buffer.alloc(1024, 0x82)))
	for (let i = 0; i < 6 && !err; i++) {
		session._onData(frame.build(frame.TYPE.CONTINUATION, 0, 1, Buffer.alloc(64 * 1024, 0x82)))
	}
	assert.ok(err, 'flood should surface an error')
	assert.ok(/too large|connection error/.test(err.message), `expected a size error, got ${err.message}`)
})
