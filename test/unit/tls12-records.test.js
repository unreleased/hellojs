// TLS 1.2 record codec — AEAD (GCM/ChaCha20) + CBC round-trip.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const records = require('../../lib/tls/tls12_records')

test('AEAD AAD layout: seq(8) + type(1) + version(2) + length(2) = 13 bytes', () => {
	const aad = records.aeadAAD(0x1234, 0x16, 100)
	assert.strictEqual(aad.length, 13)
	assert.strictEqual(aad.readUInt32BE(4), 0x1234)   // seq low 4 bytes
	assert.strictEqual(aad[8], 0x16)                  // type
	assert.strictEqual(aad[9], 0x03); assert.strictEqual(aad[10], 0x03)
	assert.strictEqual(aad.readUInt16BE(11), 100)
})

test('AES-128-GCM round-trip: encrypt+decrypt recovers plaintext', () => {
	const cipher = { aead: 'aes-128-gcm', name: 'TEST' }
	const keys = { key: crypto.randomBytes(16), iv: crypto.randomBytes(4) }
	const plaintext = Buffer.from('hello tls 1.2 application data')
	const record = records.encryptRecord(cipher, keys, 0, 0x17, plaintext)
	// Strip 5-byte record header to get the fragment
	const fragment = record.subarray(5)
	const decoded = records.decryptRecord(cipher, keys, 0, 0x17, fragment)
	assert.deepStrictEqual(decoded, plaintext)
})

test('AES-256-GCM round-trip', () => {
	const cipher = { aead: 'aes-256-gcm', name: 'TEST' }
	const keys = { key: crypto.randomBytes(32), iv: crypto.randomBytes(4) }
	const plaintext = crypto.randomBytes(200)
	const record = records.encryptRecord(cipher, keys, 5, 0x17, plaintext)
	const decoded = records.decryptRecord(cipher, keys, 5, 0x17, record.subarray(5))
	assert.deepStrictEqual(decoded, plaintext)
})

test('ChaCha20-Poly1305 round-trip', () => {
	const cipher = { aead: 'chacha20-poly1305', name: 'TEST' }
	const keys = { key: crypto.randomBytes(32), iv: crypto.randomBytes(12) }
	const plaintext = Buffer.from('chacha20 record content')
	const record = records.encryptRecord(cipher, keys, 1, 0x16, plaintext)
	const decoded = records.decryptRecord(cipher, keys, 1, 0x16, record.subarray(5))
	assert.deepStrictEqual(decoded, plaintext)
})

test('AEAD: decrypt fails with wrong key', () => {
	const cipher = { aead: 'aes-128-gcm', name: 'TEST' }
	const keys = { key: crypto.randomBytes(16), iv: crypto.randomBytes(4) }
	const wrongKeys = { key: crypto.randomBytes(16), iv: keys.iv }
	const record = records.encryptRecord(cipher, keys, 0, 0x17, Buffer.from('secret'))
	assert.throws(() => records.decryptRecord(cipher, wrongKeys, 0, 0x17, record.subarray(5)))
})

test('AEAD: decrypt fails with wrong seq number', () => {
	const cipher = { aead: 'aes-128-gcm', name: 'TEST' }
	const keys = { key: crypto.randomBytes(16), iv: crypto.randomBytes(4) }
	const record = records.encryptRecord(cipher, keys, 0, 0x17, Buffer.from('secret'))
	assert.throws(() => records.decryptRecord(cipher, keys, 1, 0x17, record.subarray(5)))
})

test('CBC AES-128-SHA round-trip', () => {
	const cipher = { aead: null, mac: 'sha1', macLen: 20, name: 'CBC-SHA' }
	const encKey = crypto.randomBytes(16)
	const macKey = crypto.randomBytes(20)
	const plaintext = Buffer.from('cbc data', 'utf8')
	const record = records.encryptRecord(cipher, { key: encKey, mac: macKey }, 0, 0x17, plaintext)
	const decoded = records.decryptRecord(cipher, { key: encKey, mac: macKey }, 0, 0x17, record.subarray(5))
	assert.deepStrictEqual(decoded, plaintext)
})

test('CBC: MAC mismatch is detected', () => {
	const cipher = { aead: null, mac: 'sha1', macLen: 20, name: 'CBC-SHA' }
	const encKey = crypto.randomBytes(16)
	const macKey = crypto.randomBytes(20)
	const wrongMacKey = crypto.randomBytes(20)
	const record = records.encryptRecord(cipher, { key: encKey, mac: macKey }, 0, 0x17, Buffer.from('data'))
	assert.throws(() => records.decryptRecord(cipher, { key: encKey, mac: wrongMacKey }, 0, 0x17, record.subarray(5)),
		/MAC mismatch/)
})
