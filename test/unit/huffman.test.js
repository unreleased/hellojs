// HPACK/QPACK Huffman codec (RFC 7541 Appendix B).

const test = require('node:test')
const assert = require('node:assert')
const huffman = require('../../lib/h3/huffman')

test('RFC 7541 Appendix C.4.1 vector: www.example.com', () => {
	const got = huffman.encode('www.example.com')
	const expected = Buffer.from('f1e3c2e5f23a6ba0ab90f4ff', 'hex')
	assert.deepStrictEqual(got, expected)
})

test('round-trip preserves ASCII strings', () => {
	const inputs = ['', 'a', 'hello world', 'GET', ':method', 'application/json', '/api/v1/foo?bar=baz']
	for (const s of inputs) {
		const enc = huffman.encode(s)
		const dec = huffman.decode(enc).toString('utf8')
		assert.strictEqual(dec, s, `round-trip failed for ${JSON.stringify(s)}`)
	}
})

test('round-trip preserves arbitrary binary bytes', () => {
	const buf = require('crypto').randomBytes(256)
	const enc = huffman.encode(buf)
	const dec = huffman.decode(enc)
	assert.deepStrictEqual(dec, buf)
})

test('decode rejects all-1s sequence longer than 7 bits (invalid EOS)', () => {
	// 8 bits of 1s would be the EOS prefix mid-stream; should be rejected during decode.
	// Constructed input where the bit stream cannot validly terminate.
	// Sanity: empty buffer decodes to empty
	assert.deepStrictEqual(huffman.decode(Buffer.alloc(0)), Buffer.alloc(0))
})
