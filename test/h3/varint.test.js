const test = require('node:test')
const assert = require('node:assert')
const v = require('../../lib/h3/varint')

// RFC 9000 Appendix A.1 test vectors
test('varint encode/decode round-trip', () => {
	const cases = [
		{ value: 0, hex: '00' },
		{ value: 25, hex: '19' },
		{ value: 63, hex: '3f' },
		{ value: 64, hex: '4040' },           // 14-bit
		{ value: 16383, hex: '7fff' },
		{ value: 16384, hex: '80004000' },    // 30-bit
		{ value: 1073741823, hex: 'bfffffff' },
		{ value: 1073741824, hex: 'c000000040000000' }, // 62-bit
	]
	for (const c of cases) {
		const enc = v.encode(c.value)
		assert.strictEqual(enc.toString('hex'), c.hex, `encode(${c.value})`)
		const dec = v.decode(enc, 0)
		assert.strictEqual(dec.value, c.value, `decode(${c.hex})`)
	}
})

// RFC 9000 §16 example: 0x9d7f3e7d should decode to 494878333
test('varint RFC §16 example', () => {
	const buf = Buffer.from('9d7f3e7d', 'hex')
	const { value, length } = v.decode(buf, 0)
	assert.strictEqual(value, 494878333)
	assert.strictEqual(length, 4)
})
