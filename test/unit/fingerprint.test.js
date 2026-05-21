// Tests for lib/tls/fingerprint.js — parseClientHello + ja3 + ja4. Plus an end-to-end check
// that the JA3 hellojs computes from the CH it just emitted matches the middlebox parrot's
// stated JA3 hash (so users can run profiles.verify(...) without round-tripping through peet).

const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')
const { Writable } = require('node:stream')
const { TLS } = require('../../lib/tls/tls')
const profiles = require('../../lib/profiles')
const { parseClientHello, ja3, ja4, isGrease } = require('../../lib/tls/fingerprint')

test('isGrease: recognises GREASE codepoints', () => {
	assert.strictEqual(isGrease(0x0a0a), true)
	assert.strictEqual(isGrease(0xfafa), true)
	assert.strictEqual(isGrease(0xeaea), true)
	assert.strictEqual(isGrease(0x1301), false)
	assert.strictEqual(isGrease(0x00ff), false)
	assert.strictEqual(isGrease(0x0a00), false)
	assert.strictEqual(isGrease(0xa0a0), false)
})

// Run a synchronous CH emission and return the captured record + parsed structure.
function emitCh(profileName) {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: profileName })
	const chunks = []
	tls.socket = new Writable({ write(chunk, _enc, cb) { chunks.push(chunk); cb() } })
	tls.mlkemPk = Buffer.alloc(1184)
	tls.startClientHello()
	const rec = Buffer.concat(chunks)
	return { tls, rec, parsed: parseClientHello(rec) }
}

test('ja3 over chrome147 CH excludes GREASE codepoints in version, ciphers, exts, groups', () => {
	const { parsed } = emitCh('chrome147-mac')
	const j = ja3(parsed)
	// Format: version,ciphers,extensions,groups,point_formats
	const [verStr, ciphersStr, extsStr, groupsStr] = j.str.split(',')
	assert.strictEqual(verStr, '771')
	// No GREASE values anywhere in the string parts.
	const allCodes = [...ciphersStr.split('-'), ...extsStr.split('-'), ...groupsStr.split('-')]
		.filter(Boolean).map(Number)
	for (const c of allCodes) assert.ok(!isGrease(c), `JA3 contains GREASE ${c.toString(16)}`)
})

test('ja3 + ja4 are recorded on TLS.actualFingerprint after startClientHello', () => {
	const { tls } = emitCh('chrome147-mac')
	assert.ok(tls.actualFingerprint, 'actualFingerprint set')
	assert.match(tls.actualFingerprint.ja3, /^[0-9a-f]{32}$/)
	assert.match(tls.actualFingerprint.ja4, /^t\d\d[di]\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$/)
})

test('ja3 over the middlebox parrot reproduces the fixture hash', () => {
	const SAMPLE = JSON.parse(fs.readFileSync(
		path.join(__dirname, '../fixtures/middlebox-tls12-peet.json'), 'utf8'))
	profiles.registerFromPeet('middlebox-tls12-fp', SAMPLE)
	const { tls } = emitCh('middlebox-tls12-fp')
	// The fixture's ja3_hash is the canonical hash computed by peet.ws's pipeline. If our
	// fingerprint module disagrees, either the JA3 algorithm or the CH bytes diverged.
	assert.strictEqual(tls.actualFingerprint.ja3, SAMPLE.tls.ja3_hash)
})

test('ja4 over the middlebox parrot reproduces the JA4_a prefix from the fixture', () => {
	const SAMPLE = JSON.parse(fs.readFileSync(
		path.join(__dirname, '../fixtures/middlebox-tls12-peet.json'), 'utf8'))
	const expectedPrefix = SAMPLE.tls.ja4.split('_')[0]   // e.g. "t12d1310h2"
	const { tls } = emitCh('middlebox-tls12-fp')
	const actualPrefix = tls.actualFingerprint.ja4.split('_')[0]
	assert.strictEqual(actualPrefix, expectedPrefix)
})

test('"fingerprint" event fires synchronously during startClientHello', () => {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: 'chrome147-mac' })
	tls.socket = new Writable({ write(_c, _e, cb) { cb() } })
	tls.mlkemPk = Buffer.alloc(1184)
	let seen = null
	tls.on('fingerprint', (fp) => { seen = fp })
	tls.startClientHello()
	assert.ok(seen, 'fingerprint event was emitted')
	assert.match(seen.ja3, /^[0-9a-f]{32}$/)
})
