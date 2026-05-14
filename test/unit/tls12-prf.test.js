// TLS 1.2 PRF — P_SHA256/P_SHA384, master_secret, EMS, key_block, finished verify_data.
// PRF is the heart of TLS 1.2 key derivation. If this is wrong, nothing else works.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const prf = require('../../lib/tls/tls12_prf')

test('P_SHA256 matches a hand-rolled HMAC chain', () => {
	const secret = Buffer.from('secret')
	const seed = Buffer.from('seed')
	const got = prf.pHash('sha256', secret, seed, 100)

	// Reference: P_hash(secret, seed) = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || …
	let a = seed, total = 0
	const out = []
	while (total < 100) {
		a = crypto.createHmac('sha256', secret).update(a).digest()
		const b = crypto.createHmac('sha256', secret).update(a).update(seed).digest()
		out.push(b)
		total += b.length
	}
	const expected = Buffer.concat(out).subarray(0, 100)
	assert.deepStrictEqual(got, expected)
})

test('prf(secret, label, seed) == pHash(secret, label||seed)', () => {
	const pms = Buffer.alloc(48, 0)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const ms = prf.masterSecret('sha256', pms, cr, sr)
	const direct = prf.pHash('sha256', pms, Buffer.concat([Buffer.from('master secret'), cr, sr]), 48)
	assert.deepStrictEqual(ms, direct)
})

test('masterSecret is 48 bytes regardless of PRF hash', () => {
	const pms = Buffer.alloc(48, 0)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	assert.strictEqual(prf.masterSecret('sha256', pms, cr, sr).length, 48)
	assert.strictEqual(prf.masterSecret('sha384', pms, cr, sr).length, 48)
})

test('extendedMasterSecret diverges from masterSecret with same PMS', () => {
	const pms = Buffer.alloc(48, 0x42)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const sessionHash = Buffer.alloc(32, 0xcc)
	const normal = prf.masterSecret('sha256', pms, cr, sr)
	const ems = prf.extendedMasterSecret('sha256', pms, sessionHash)
	assert.notDeepStrictEqual(normal, ems, 'EMS must differ from standard MS')
})

test('keyBlock seed order is server_random || client_random (NOT cr||sr)', () => {
	const ms = Buffer.alloc(48, 0x42)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const right = prf.keyBlock('sha256', ms, sr, cr, 40)
	const wrong = prf.keyBlock('sha256', ms, cr, sr, 40)
	assert.notDeepStrictEqual(right, wrong, 'sr||cr and cr||sr must produce different key blocks')
})

test('finishedVerifyData is exactly 12 bytes', () => {
	const ms = Buffer.alloc(48, 0x42)
	const h = Buffer.alloc(32, 0xcc)
	assert.strictEqual(prf.finishedVerifyData('sha256', ms, true, h).length, 12)
	assert.strictEqual(prf.finishedVerifyData('sha384', ms, false, h).length, 12)
})

test('finishedVerifyData differs by side (client vs server) and by transcript', () => {
	const ms = Buffer.alloc(48, 0x42)
	const h1 = Buffer.alloc(32, 0xcc)
	const h2 = Buffer.alloc(32, 0xdd)
	const c1 = prf.finishedVerifyData('sha256', ms, true, h1)
	const s1 = prf.finishedVerifyData('sha256', ms, false, h1)
	const c2 = prf.finishedVerifyData('sha256', ms, true, h2)
	assert.notDeepStrictEqual(c1, s1)
	assert.notDeepStrictEqual(c1, c2)
})
