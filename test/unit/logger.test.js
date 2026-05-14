// Logger: levels + JSON mode.

const test = require('node:test')
const assert = require('node:assert')
const logger = require('../../lib/models/log')

function captureLogs(fn) {
	const orig = console.log
	const out = []
	console.log = (s) => out.push(s)
	try { fn() } finally { console.log = orig }
	return out
}

test('default level is off (silent)', () => {
	logger.setLevel('off')
	const log = logger('[t]')
	const out = captureLogs(() => { log.error('err'); log.warn('warn'); log.notify('info') })
	assert.deepStrictEqual(out, [])
})

test('level=info shows info/warn/error but not debug/trace', () => {
	logger.setLevel('info')
	const log = logger('[t]')
	const out = captureLogs(() => { log.error('err'); log.warn('warn'); log.notify('info'); log.debug('debug'); log.trace('trace') })
	assert.strictEqual(out.length, 3)
})

test('JSON mode emits JSON-line records', () => {
	logger.setLevel('info')
	logger.setJsonMode(true)
	try {
		const log = logger('[tls]')
		const out = captureLogs(() => log.notify('handshake complete', { ms: 42 }))
		assert.strictEqual(out.length, 1)
		const rec = JSON.parse(out[0])
		assert.strictEqual(rec.level, 'info')
		assert.strictEqual(rec.mod, '[tls]')
		assert.match(rec.msg, /handshake complete/)
		assert.match(rec.msg, /"ms":42/)
		assert.ok(rec.ts && new Date(rec.ts).toString() !== 'Invalid Date')
	} finally {
		logger.setJsonMode(false)
		logger.setLevel('off')
	}
})

test('JSON mode survives non-serializable args (no crash)', () => {
	logger.setLevel('error')
	logger.setJsonMode(true)
	try {
		const log = logger('[t]')
		const circular = {}; circular.self = circular
		const out = captureLogs(() => log.error('oops', circular))
		assert.strictEqual(out.length, 1)
		// Just verify it didn't throw and produced a record.
		const rec = JSON.parse(out[0])
		assert.strictEqual(rec.level, 'error')
	} finally {
		logger.setJsonMode(false)
		logger.setLevel('off')
	}
})
