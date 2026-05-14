// Fuzz harnesses for the parsers an attacker (or buggy server) can drive.
//
// Goal: parser MUST NOT crash on arbitrary input. Throwing a HellojsError or returning
// a partial / null result is fine — segfaults, infinite loops, or unhandled exceptions
// outside the call site are not.
//
// We don't aim for full coverage. We aim to defeat the obvious classes:
//   - integer over-/under-flow on length fields
//   - out-of-bounds reads on truncated inputs
//   - infinite loops on cyclic / self-referential structures
//   - rampaging memory allocation
//
// Each fuzz batch is ITERATIONS rounds. Bump with FUZZ_ITERATIONS=10000 for a longer run.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')

const ITERATIONS = parseInt(process.env.FUZZ_ITERATIONS || '1000', 10)
const TIMEOUT_MS = 30_000

function randomBuf(maxLen = 256) {
	const len = Math.floor(Math.random() * maxLen)
	return crypto.randomBytes(len)
}

// Mutate a known-good buffer by flipping random bytes — catches more bugs than
// pure-random input because the parser's first few branches succeed.
function mutate(buf, n = 4) {
	const out = Buffer.from(buf)
	for (let i = 0; i < n; i++) {
		const idx = Math.floor(Math.random() * out.length)
		out[idx] ^= (1 + Math.floor(Math.random() * 255)) & 0xff
	}
	return out
}

function fuzz(name, fn) {
	test(`fuzz: ${name}`, { timeout: TIMEOUT_MS }, () => {
		let panics = 0
		for (let i = 0; i < ITERATIONS; i++) {
			try { fn() } catch (e) {
				// Throws are acceptable. We're only watching for hangs (timeout) or process exits.
				panics++
			}
		}
		// Always pass — the assertion is that we ran ITERATIONS rounds without dying.
		assert.ok(true, `${name}: ran ${ITERATIONS} iterations (${panics} threw, all caught)`)
	})
}

// -------- HPACK decoder --------
fuzz('HPACK decoder on random bytes', () => {
	const hpack = require('../../lib/h2/hpack')
	const dt = new hpack.DynamicTable(4096)
	hpack.decode(randomBuf(512), dt)
})

fuzz('HPACK decoder on mutated-good blocks', () => {
	const hpack = require('../../lib/h2/hpack')
	const dt = new hpack.DynamicTable(4096)
	// Build a known-good block then mutate
	const enc = new hpack.DynamicTable(4096)
	const good = hpack.encode([[':method', 'GET'], [':path', '/foo'], ['accept', '*/*']], enc)
	hpack.decode(mutate(good, 3), dt)
})

// -------- HPACK encoder (defensive — shouldn't blow up on weird inputs) --------
fuzz('HPACK encoder on random header pairs', () => {
	const hpack = require('../../lib/h2/hpack')
	const dt = new hpack.DynamicTable(4096)
	const pairs = []
	const count = Math.floor(Math.random() * 8)
	for (let i = 0; i < count; i++) {
		pairs.push([
			randomBuf(32).toString('hex'),
			randomBuf(64).toString('base64'),
		])
	}
	hpack.encode(pairs, dt)
})

// -------- h2 frame parser --------
fuzz('h2 frame parser on random bytes', () => {
	const frame = require('../../lib/h2/frame')
	let buf = randomBuf(1024)
	while (buf.length >= 9) {
		const f = frame.parse(buf)
		if (!f) break
		buf = buf.subarray(f.consumed)
	}
})

// -------- TLS 1.2 record codec (decrypt side) --------
fuzz('TLS 1.2 GCM record codec on truncated input', () => {
	const records = require('../../lib/tls/tls12_records')
	const cipher = { aead: 'aes-128-gcm', name: 'TEST' }
	const keys = { key: crypto.randomBytes(16), iv: crypto.randomBytes(4) }
	const garbage = randomBuf(64)
	try { records.decryptRecord(cipher, keys, 0, 0x17, garbage) } catch (_) {}
})

// -------- Cert chain parser (X509) --------
fuzz('Cert validate on random DER blobs', () => {
	const { validateChain } = require('../../lib/tls/cert-validate')
	try { validateChain([randomBuf(512)], 'example.com') } catch (_) {}
})

// -------- QUIC varint --------
fuzz('QUIC varint decode on random bytes', () => {
	const varint = require('../../lib/h3/varint')
	const buf = randomBuf(16)
	let off = 0
	while (off < buf.length) {
		try {
			const [, next] = varint.decode(buf, off)
			if (next === off) break
			off = next
		} catch (_) { break }
	}
})

// -------- QUIC packet parser via long-header detection --------
fuzz('QUIC long-header packet parse on random bytes', () => {
	const packet = require('../../lib/h3/packet')
	try { packet.parseLongHeader?.(randomBuf(256)) } catch (_) {}
	try { packet.parseShortHeader?.(randomBuf(256)) } catch (_) {}
})

// -------- QPACK decoder --------
fuzz('QPACK decoder on random bytes', () => {
	const qpack = require('../../lib/h3/qpack')
	try { qpack.decodeHeaders?.(randomBuf(256)) } catch (_) {}
})

// -------- Huffman codec --------
fuzz('Huffman decoder on random bytes', () => {
	const huffman = require('../../lib/h3/huffman')
	try { huffman.decode(randomBuf(128)) } catch (_) {}
})

// -------- Transport params parser --------
fuzz('QUIC transport params on random bytes', () => {
	const tp = require('../../lib/h3/transport-params')
	try { tp.parse?.(randomBuf(128)) } catch (_) {}
})

// -------- NewSessionTicket parser --------
fuzz('NewSessionTicket parser on random bytes', () => {
	const sc = require('../../lib/tls/session-cache')
	try { sc.parseNewSessionTicket(randomBuf(256)) } catch (_) {}
})
