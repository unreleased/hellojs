// OCSP stapled-response parser tests. We don't have a stable test vector library, so we
// build minimal hand-rolled DER for the happy paths.

const test = require('node:test')
const assert = require('node:assert')
const { parseOcspResponse } = require('../../lib/tls/ocsp')

// Build a SEQUENCE prefixed with tag 0x30 + length.
function seq(content) {
	const c = Buffer.concat(content)
	return Buffer.concat([Buffer.from([0x30, c.length]), c])
}
function enumerated(v) { return Buffer.from([0x0a, 1, v]) }
function expl0(content) { return Buffer.concat([Buffer.from([0xa0, content.length]), content]) }
function expl1(content) { return Buffer.concat([Buffer.from([0xa1, content.length]), content]) }
function octStr(content) { return Buffer.concat([Buffer.from([0x04, content.length]), content]) }
function oid(b) { return Buffer.concat([Buffer.from([0x06, b.length]), b]) }
function genTime(s) { return Buffer.concat([Buffer.from([0x18, s.length]), Buffer.from(s)]) }
function ctxImplicit(tag, content) { return Buffer.concat([Buffer.from([tag, content.length]), content]) }

// Construct a minimal SuccessfulOcspResponse with one SingleResponse whose certStatus is `tag`.
// tag: 0x80 (good), 0xa1 (revoked), 0x82 (unknown).
function buildResp(certStatusTag) {
	const singleResp = seq([
		seq([Buffer.alloc(0)]),                       // certID (empty SEQUENCE placeholder)
		ctxImplicit(certStatusTag, Buffer.alloc(0)),  // certStatus
		genTime('20260513120000Z'),                   // thisUpdate
	])
	const responses = seq([singleResp])
	const responderIdName = expl1(seq([Buffer.alloc(0)]))     // [1] EXPLICIT Name
	const producedAt = genTime('20260513120000Z')
	const tbs = seq([responderIdName, producedAt, responses])

	const basicOCSP = seq([
		tbs,
		seq([oid(Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]))]),  // signatureAlgorithm (faked)
		Buffer.from([0x03, 0x01, 0x00]),              // signature BIT STRING (empty)
	])

	const responseBytes = expl0(seq([
		oid(Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01])),  // basic OCSP OID
		octStr(basicOCSP),
	]))

	return seq([
		enumerated(0),     // successful
		responseBytes,
	])
}

test('parses OCSP responseStatus=successful + cert status=good', () => {
	const der = buildResp(0x80)
	const r = parseOcspResponse(der)
	assert.strictEqual(r.responseStatus, 'successful')
	assert.deepStrictEqual(r.statuses, ['good'])
})

test('parses cert status=revoked', () => {
	const der = buildResp(0xa1)
	const r = parseOcspResponse(der)
	assert.strictEqual(r.responseStatus, 'successful')
	assert.deepStrictEqual(r.statuses, ['revoked'])
})

test('parses cert status=unknown', () => {
	const der = buildResp(0x82)
	const r = parseOcspResponse(der)
	assert.strictEqual(r.responseStatus, 'successful')
	assert.deepStrictEqual(r.statuses, ['unknown'])
})

test('handles malformedRequest (non-successful) without crashing', () => {
	const der = Buffer.concat([
		Buffer.from([0x30, 0x03]),
		Buffer.from([0x0a, 0x01, 0x01]),  // ENUMERATED 1 = malformedRequest
	])
	const r = parseOcspResponse(der)
	assert.strictEqual(r.responseStatus, 'malformedRequest')
	assert.deepStrictEqual(r.statuses, [])
})

test('handles empty buffer', () => {
	const r = parseOcspResponse(Buffer.alloc(0))
	assert.strictEqual(r.responseStatus, null)
})
