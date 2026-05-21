// End-to-end Phase 1-4 regression: register the user's middlebox-tls12 parrot as a profile,
// drive TLS.startClientHello() against a fake socket, parse the captured ClientHello, and
// assert that what hit the wire matches the parrot. No real network.

const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')
const { Writable } = require('node:stream')

const { TLS } = require('../../lib/tls/tls')
const profiles = require('../../lib/profiles')

const SAMPLE_PATH = path.join(__dirname, '../fixtures/middlebox-tls12-peet.json')
const SAMPLE = JSON.parse(fs.readFileSync(SAMPLE_PATH, 'utf8'))

// Minimal ClientHello parser. Returns { ciphers, extensionIds, extensionMap } where
// extensionMap[id] is the extension body Buffer (without the 4-byte header).
function parseClientHello(rec) {
	// Record header (5) + handshake header (4) → ClientHello body
	assert.strictEqual(rec[0], 0x16, 'record type should be handshake')
	const recLen = rec.readUInt16BE(3)
	assert.strictEqual(5 + recLen, rec.length, 'record length matches')
	const hs = rec.subarray(5)
	assert.strictEqual(hs[0], 0x01, 'handshake type should be ClientHello')
	const hsLen = (hs[1] << 16) | (hs[2] << 8) | hs[3]
	assert.strictEqual(4 + hsLen, hs.length, 'handshake length matches')
	let o = 4
	o += 2          // legacy_version
	o += 32         // random
	const sidLen = hs[o]; o += 1 + sidLen
	const csLen = hs.readUInt16BE(o); o += 2
	const ciphers = []
	for (let i = 0; i < csLen; i += 2) ciphers.push(hs.readUInt16BE(o + i))
	o += csLen
	const cmLen = hs[o]; o += 1 + cmLen   // compression methods
	const extsLen = hs.readUInt16BE(o); o += 2
	const extsEnd = o + extsLen
	const extensionIds = []
	const extensionMap = {}
	while (o < extsEnd) {
		const id = hs.readUInt16BE(o); o += 2
		const len = hs.readUInt16BE(o); o += 2
		extensionIds.push(id)
		extensionMap[id] = hs.subarray(o, o + len)
		o += len
	}
	return { ciphers, extensionIds, extensionMap }
}

function makeTls(profileName) {
	// TLS constructor is (host, port, proxy, opts) — proxy in 3rd arg, opts in 4th.
	const tls = new TLS('tls.peet.ws', 443, null, { profile: profileName })
	// startClientHello writes to this.socket.write — install a buffer-capturing fake.
	const chunks = []
	tls.socket = new Writable({
		write(chunk, _enc, cb) { chunks.push(chunk); cb() },
	})
	// In TLS 1.2-only mode startClientHello uses this.mlkemPk only when _profileNeedsMlkem();
	// for TLS 1.3 profiles set a stub here so we don't have to call connect() (which opens TCP).
	tls.mlkemPk = Buffer.alloc(1184)
	return { tls, getCh: () => Buffer.concat(chunks) }
}

test('middlebox parrot composes a valid ClientHello with the right shape', () => {
	const p = profiles.registerFromPeet('middlebox-tls12', SAMPLE)
	// Sanity: profile is configured for no-GREASE + TLS-1.2-only.
	assert.strictEqual(p.tls.useGrease, false)
	assert.deepStrictEqual(p.tls.supportedVersions, [0x0303])

	const { tls, getCh } = makeTls('middlebox-tls12')
	tls.startClientHello()
	const { ciphers, extensionIds, extensionMap } = parseClientHello(getCh())

	// (Phase 1) Cipher list: SCSV (0x00ff) present, no GREASE codepoint.
	assert.ok(ciphers.includes(0x00ff), 'SCSV (0x00ff) in cipher list')
	assert.ok(ciphers.every(c => (c & 0x0f0f) !== 0x0a0a),
		'no GREASE codepoint in cipher list when useGrease=false')

	// (Phase 2) Extensions 17 and 50 emitted (not silently dropped).
	assert.ok(extensionIds.includes(17), 'status_request_v2 (17) in ClientHello')
	assert.ok(extensionIds.includes(50), 'signature_algorithms_cert (50) in ClientHello')

	// (Phase 2) signature_algorithms_cert body must equal the raw bytes captured from peet.
	const expectedRaw = Buffer.from(
		'00260403050306030804080508060809080a080b0401050106010402030303010302020302010202',
		'hex')
	assert.ok(expectedRaw.equals(extensionMap[50]),
		'signature_algorithms_cert body is byte-identical to fixture')

	// (Phase 3) No GREASE extension bookends.
	assert.ok(extensionIds.every(id => (id & 0x0f0f) !== 0x0a0a),
		'no GREASE extension when useGrease=false')

	// (Phase 4) No key_share (id 51) — the profile is TLS-1.2-only.
	assert.ok(!extensionIds.includes(51), 'no key_share for TLS-1.2-only profile')

	// supported_versions body: u8 list length || u16 each. Must be 0x0303 only (no GREASE).
	const sv = extensionMap[43]
	assert.strictEqual(sv[0], 2, 'supported_versions list length = 2 (one TLS version)')
	assert.strictEqual(sv.readUInt16BE(1), 0x0303, 'only TLS 1.2 advertised')

	// supported_groups: u16 list length || u16 each. Five groups, no GREASE.
	const sg = extensionMap[10]
	const sgListLen = sg.readUInt16BE(0)
	assert.strictEqual(sgListLen, 10, '5 groups × 2 bytes = 10')
	const offered = []
	for (let i = 0; i < sgListLen; i += 2) offered.push(sg.readUInt16BE(2 + i))
	assert.deepStrictEqual(offered, [0x001d, 0x0017, 0x0018, 0x0019, 0x001e])
})

test('chrome147-mac still emits GREASE everywhere expected', () => {
	const { tls, getCh } = makeTls('chrome147-mac')
	tls.startClientHello()
	const { ciphers, extensionIds, extensionMap } = parseClientHello(getCh())

	// Cipher GREASE at the front (any 0x?a?a where high and low nibbles match the GREASE pattern).
	assert.strictEqual((ciphers[0] & 0x0f0f), 0x0a0a, 'first cipher is GREASE')

	// First and last extension are GREASE.
	assert.strictEqual(extensionIds[0] & 0x0f0f, 0x0a0a)
	assert.strictEqual(extensionIds[extensionIds.length - 1] & 0x0f0f, 0x0a0a)

	// supported_versions starts with GREASE then 0x0304, 0x0303.
	const sv = extensionMap[43]
	assert.strictEqual(sv[0], 6)
	assert.strictEqual(sv.readUInt16BE(1) & 0x0f0f, 0x0a0a)
	assert.strictEqual(sv.readUInt16BE(3), 0x0304)
	assert.strictEqual(sv.readUInt16BE(5), 0x0303)
})
