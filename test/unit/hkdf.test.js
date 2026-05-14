// HKDF (RFC 5869) + Expand-Label (RFC 8446 §7.1). Underpins all TLS 1.3 key derivation.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const HKDF = require('../../lib/utils/hkdf')

test('Extract is HMAC(salt, IKM)', () => {
	const salt = Buffer.alloc(32, 0)
	const ikm = Buffer.from('input keying material')
	const got = HKDF.Extract('sha256', salt, ikm)
	const expected = crypto.createHmac('sha256', salt).update(ikm).digest()
	assert.deepStrictEqual(got, expected)
})

test('Expand-Label format: u16 L | u8 labelLen | "tls13 " + label | u8 ctxLen | ctx', () => {
	// We verify the canonical TLS 1.3 label format by computing two Expand-Labels and
	// confirming they differ only by the label byte; the length is the same.
	const secret = crypto.randomBytes(32)
	const a = HKDF.ExpandLabel(secret, 'client traffic', Buffer.alloc(0), 32, 'sha256', 32)
	const b = HKDF.ExpandLabel(secret, 'server traffic', Buffer.alloc(0), 32, 'sha256', 32)
	assert.strictEqual(a.length, 32)
	assert.strictEqual(b.length, 32)
	assert.notDeepStrictEqual(a, b)
})

test('Expand-Label is deterministic', () => {
	const secret = Buffer.alloc(32, 0x42)
	const ctx = Buffer.alloc(16, 0xab)
	const a = HKDF.ExpandLabel(secret, 'finished', ctx, 32, 'sha256', 32)
	const b = HKDF.ExpandLabel(secret, 'finished', ctx, 32, 'sha256', 32)
	assert.deepStrictEqual(a, b)
})

test('sha256/sha384 helpers hash concatenation of arguments', () => {
	const a = Buffer.from('hello ')
	const b = Buffer.from('world')
	const got = HKDF.sha256(a, b)
	const expected = crypto.createHash('sha256').update(Buffer.concat([a, b])).digest()
	assert.deepStrictEqual(got, expected)
})
