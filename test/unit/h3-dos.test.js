// Tier-2 remote-DoS hardening for the QUIC/HTTP-3 transport: a malicious or buggy server must not
// be able to crash the client process or freeze the event loop or exhaust memory.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const { QuicConnection, QuicStream } = require('../../lib/h3/connection')

test('_onDatagram drops malformed/garbage datagrams without throwing', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	c.on('error', () => {})
	for (let i = 0; i < 300; i++) {
		const buf = crypto.randomBytes(1 + (i % 80))
		assert.doesNotThrow(() => c._onDatagram(buf, { address: '127.0.0.1', port: 443 }))
	}
	// long-header-shaped garbage + truncated short-header packet
	assert.doesNotThrow(() => c._onDatagram(Buffer.from([0xc0, 0, 0, 0, 1, 8, ...new Array(20).fill(0xab)])))
	assert.doesNotThrow(() => c._onDatagram(Buffer.from([0x40, 0x01])))
	assert.doesNotThrow(() => c._onDatagram(Buffer.alloc(0)))
})

test('malicious ACK range does not freeze the event loop', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	for (const pn of [0, 1, 2, 3, 4, 5]) {
		c.sentPackets.oneRtt.set(pn, { size: 100, time: 0, ackEliciting: true, inFlight: true })
	}
	const start = process.hrtime.bigint()
	// largestAcked tiny, firstAckRange astronomically large -> old code looped ~1e15 times.
	c._handleFrame('oneRtt', { type: 'ack', largestAcked: 5, firstAckRange: 1e15, ranges: [] })
	const ms = Number(process.hrtime.bigint() - start) / 1e6
	assert.ok(ms < 250, `ack handling took ${ms}ms (should be ~instant)`)
	// The 6 outstanding packets fell inside the (huge) range and were acked.
	assert.strictEqual(c.sentPackets.oneRtt.size, 0)
})

test('ACK still acks exactly the packets within the declared ranges', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	for (const pn of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) {
		c.sentPackets.oneRtt.set(pn, { size: 100, time: 0, ackEliciting: true, inFlight: true })
	}
	// largestAcked=10, firstAckRange=1 -> acks 9,10; then gap=1 (skips 8,7), range len=1 -> acks 5,6.
	c._handleFrame('oneRtt', { type: 'ack', largestAcked: 10, firstAckRange: 1, ranges: [{ gap: 1, length: 1 }] })
	const remaining = [...c.sentPackets.oneRtt.keys()].sort((a, b) => a - b)
	assert.deepStrictEqual(remaining, [0, 1, 2, 3, 4, 7, 8])
})

test('stream out-of-order reassembly buffer is bounded', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	const s = new QuicStream(c, 0)
	let errored = false
	s.on('error', () => { errored = true })
	s.on('data', () => {})
	// Feed 1 MiB chunks at ever-increasing, never-in-order offsets (recvOffset stays 0).
	const chunk = Buffer.alloc(1024 * 1024, 0xab)
	for (let i = 0; i < 64 && !errored; i++) s._onData((i + 1) * 1e9, chunk, false)
	assert.ok(errored, 'stream should error once the out-of-order buffer cap is exceeded')
	assert.ok(s._pendingBytes <= 8 * 1024 * 1024, `pending bytes ${s._pendingBytes} should stay bounded`)
})
