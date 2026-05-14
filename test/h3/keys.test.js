// RFC 9001 Appendix A.1 / A.2 test vectors for QUIC v1 initial keys.
const test = require('node:test')
const assert = require('node:assert')
const k = require('../../lib/h3/keys')

// RFC 9001 §A.1: Server chose dst CID = 0x8394c8f03e515708.
// Expected derived values for the client side:
const DST_CID = Buffer.from('8394c8f03e515708', 'hex')

test('initial-keys derivation matches RFC 9001 A.1 vectors', () => {
	const keys = k.deriveInitialKeys(DST_CID)
	// Per RFC 9001 A.1:
	assert.strictEqual(keys.client.secret.toString('hex'), 'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea')
	assert.strictEqual(keys.client.key.toString('hex'),    '1f369613dd76d5467730efcbe3b1a22d')
	assert.strictEqual(keys.client.iv.toString('hex'),     'fa044b2f42a3fd3b46fb255c')
	assert.strictEqual(keys.client.hp.toString('hex'),     '9f50449e04a0e810283a1e9933adedd2')
	assert.strictEqual(keys.server.secret.toString('hex'), '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b')
	assert.strictEqual(keys.server.key.toString('hex'),    'cf3a5331653c364c88f0f379b6067e37')
	assert.strictEqual(keys.server.iv.toString('hex'),     '0ac1493ca1905853b0bba03e')
	assert.strictEqual(keys.server.hp.toString('hex'),     'c206b8d9b9f0f37644430b490eeaa314')
})

test('AES header-protection mask matches RFC 9001 A.2', () => {
	// From RFC 9001 §A.2: hp_key = 9f50449e04a0e810283a1e9933adedd2,
	// sample = d1b1c98dd7689fb8ec11d242b123dc9b → mask first 5 bytes = 437b9aec36
	const mask = k.aesHeaderProtectionMask(
		Buffer.from('9f50449e04a0e810283a1e9933adedd2', 'hex'),
		Buffer.from('d1b1c98dd7689fb8ec11d242b123dc9b', 'hex'),
	)
	assert.strictEqual(mask.toString('hex'), '437b9aec36')
})
