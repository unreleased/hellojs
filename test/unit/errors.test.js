// Error taxonomy: stable shape, codes, categories, and wrap() promotion.

const test = require('node:test')
const assert = require('node:assert')
const { HellojsError, CODES, CATEGORY, wrap } = require('../../lib/errors')

test('HellojsError has stable name + code + category', () => {
	const e = new HellojsError('boom', 'EHTTP')
	assert.strictEqual(e.name, 'HellojsError')
	assert.strictEqual(e.code, 'EHTTP')
	assert.strictEqual(e.category, CATEGORY.HTTP)
	assert.ok(e instanceof Error)
})

test('Unknown code defaults to protocol category', () => {
	const e = new HellojsError('huh', 'EBOGUS')
	assert.strictEqual(e.category, CATEGORY.PROTOCOL)
})

test('wrap() passes a HellojsError through unchanged', () => {
	const src = new HellojsError('x', 'ETIMEDOUT')
	assert.strictEqual(wrap(src), src)
})

test('wrap() promotes a Node ECONNRESET error to ECONNRESET HellojsError', () => {
	const node = Object.assign(new Error('socket reset'), { code: 'ECONNRESET' })
	const e = wrap(node)
	assert.ok(e instanceof HellojsError)
	assert.strictEqual(e.code, 'ECONNRESET')
	assert.strictEqual(e.category, CATEGORY.TRANSPORT)
	assert.strictEqual(e.cause, node)
})

test('wrap() of generic Error uses fallback code EPROTO', () => {
	const node = new Error('something')
	const e = wrap(node)
	assert.strictEqual(e.code, 'EPROTO')
	assert.strictEqual(e.category, CATEGORY.PROTOCOL)
})

test('wrap(null) yields a HellojsError', () => {
	const e = wrap(null)
	assert.ok(e instanceof HellojsError)
})

test('CODES enum has every code mapped to a known CATEGORY', () => {
	const known = new Set(Object.values(CATEGORY))
	for (const [code, def] of Object.entries(CODES)) {
		assert.ok(known.has(def.category), `code ${code} has unknown category ${def.category}`)
	}
})
