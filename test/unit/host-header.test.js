// Host is builder-managed: exactly one Host (h1) / :authority (h2), even when the caller passes
// their own Host header. Two Host headers are malformed (RFC 7230 5.4) and a fingerprint tell; a
// stray `host` header over h2 is likewise a tell (Chrome carries the origin only in :authority).

const test = require('node:test')
const assert = require('node:assert')
const { buildH1Headers, buildH2Headers } = require('../../lib/headers')

function hostLines(block) {
	return block.split('\r\n').filter((l) => /^host:/i.test(l))
}

test('h1: no caller Host -> exactly one Host from the URL', () => {
	const lines = hostLines(buildH1Headers({ host: 'real.example', userHeaders: {}, profile: null }))
	assert.deepStrictEqual(lines, ['Host: real.example'])
})

test('h1: caller-supplied host does not duplicate, and overrides', () => {
	for (const key of ['host', 'Host', 'HOST']) {
		const lines = hostLines(buildH1Headers({ host: 'real.example', userHeaders: { [key]: 'override.example' }, profile: null }))
		assert.strictEqual(lines.length, 1, `expected one Host line for caller key ${key}, got ${JSON.stringify(lines)}`)
		assert.strictEqual(lines[0], 'Host: override.example')
	}
})

test('h1: Host stays first in the header block', () => {
	const block = buildH1Headers({ host: 'real.example', userHeaders: { 'x-foo': 'bar' }, profile: null })
	assert.ok(block.startsWith('Host: real.example\r\n'), 'Host must be the first header line')
})

test('h2: no caller host -> :authority from the URL, no regular host header', () => {
	const h = buildH2Headers({ method: 'GET', host: 'real.example', path: '/', userHeaders: {}, profile: null })
	assert.strictEqual(h[':authority'], 'real.example')
	assert.strictEqual(h.host, undefined)
})

test('h2: caller-supplied host overrides :authority and is not emitted as a regular header', () => {
	for (const key of ['host', 'Host', 'HOST']) {
		const h = buildH2Headers({ method: 'GET', host: 'real.example', path: '/', userHeaders: { [key]: 'override.example' }, profile: null })
		assert.strictEqual(h[':authority'], 'override.example', `:authority should reflect caller ${key}`)
		assert.strictEqual(h.host, undefined, `no regular host header should leak for caller ${key}`)
	}
})
