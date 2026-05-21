// Wire-format tests for the extension builders that Phase 2 added.

const test = require('node:test')
const assert = require('node:assert')
const {
	CreateStatusRequestExtension,
	CreateStatusRequestV2Extension,
	CreateSignatureAlgorithmsCertExtension,
	CreateSupportedGroupsExtension,
	CreateSupportedVersionsExtension,
} = require('../../lib/extensions')

test('status_request (5): default (Chrome) shape — type=1, 0/0', () => {
	const ext = CreateStatusRequestExtension()
	assert.strictEqual(ext.readUInt16BE(0), 0x0005)
	const bodyLen = ext.readUInt16BE(2)
	assert.strictEqual(bodyLen + 4, ext.length)
	assert.strictEqual(ext.readUInt8(4), 0x01)      // certificate_status_type = ocsp(1)
	assert.strictEqual(ext.readUInt16BE(5), 0)      // responder_id_list_length
	assert.strictEqual(ext.readUInt16BE(7), 0)      // request_extensions_length
})

test('status_request (5): honours non-zero shape from profile', () => {
	const ext = CreateStatusRequestExtension({
		certificateStatusType: 1,
		responderIdListLength: 0,
		requestExtensionsLength: 2,
	})
	// 1 byte type + 2 byte ridLen + 0 bytes responder list + 2 byte reqLen + 2 bytes ext data
	const bodyLen = ext.readUInt16BE(2)
	assert.strictEqual(bodyLen, 1 + 2 + 0 + 2 + 2)
	assert.strictEqual(ext.readUInt16BE(7), 2)
})

test('status_request_v2 (17): default shape', () => {
	const ext = CreateStatusRequestV2Extension()
	assert.strictEqual(ext.readUInt16BE(0), 0x0011)
	const bodyLen = ext.readUInt16BE(2)
	const listLen = ext.readUInt16BE(4)
	assert.strictEqual(listLen + 2, bodyLen)
	// Inside the list: type(1) + ridLen(2) + reqLen(2) = 5 bytes
	assert.strictEqual(ext.readUInt8(6), 0x02)
	assert.strictEqual(ext.readUInt16BE(7), 0)
	assert.strictEqual(ext.readUInt16BE(9), 0)
})

test('status_request_v2 (17): non-zero responder/request lengths', () => {
	const ext = CreateStatusRequestV2Extension({
		certificateStatusType: 0,
		responderIdListLength: 7,
		requestExtensionsLength: 2,
	})
	const bodyLen = ext.readUInt16BE(2)
	// list_len + item(type + ridLen + 7 padding + reqLen + 2 padding)
	assert.strictEqual(bodyLen, 2 + 1 + 2 + 7 + 2 + 2)
	assert.strictEqual(ext.readUInt8(6), 0)
	assert.strictEqual(ext.readUInt16BE(7), 7)
})

test('signature_algorithms_cert (50): emits raw body verbatim', () => {
	const raw = Buffer.from('00040403080a', 'hex')   // 2 sigalgs: 0x0403, 0x080a
	const ext = CreateSignatureAlgorithmsCertExtension({ raw })
	assert.strictEqual(ext.readUInt16BE(0), 0x0032)
	const bodyLen = ext.readUInt16BE(2)
	assert.strictEqual(bodyLen, raw.length)
	assert.strictEqual(ext.subarray(4).equals(raw), true)
})

test('signature_algorithms_cert (50): builds from sigalgs array', () => {
	const ext = CreateSignatureAlgorithmsCertExtension({ sigalgs: [0x0403, 0x0809] })
	assert.strictEqual(ext.readUInt16BE(0), 0x0032)
	const bodyLen = ext.readUInt16BE(2)
	assert.strictEqual(bodyLen, 2 + 4)
	assert.strictEqual(ext.readUInt16BE(4), 4)       // inner list length
	assert.strictEqual(ext.readUInt16BE(6), 0x0403)
	assert.strictEqual(ext.readUInt16BE(8), 0x0809)
})

test('signature_algorithms_cert (50): throws without raw or sigalgs', () => {
	assert.throws(() => CreateSignatureAlgorithmsCertExtension({}),
		/raw \(Buffer\) or opts\.sigalgs/)
})

test('supported_groups (10): useGrease=true prepends GREASE codepoint', () => {
	const ext = CreateSupportedGroupsExtension(0xAA, [0x001d, 0x0017])
	// hdr(2) + extLen(2) + listLen(2) + entries(3*2=6)
	assert.strictEqual(ext.length, 12)
	assert.strictEqual(ext.readUInt16BE(6), 0xAAAA)  // GREASE
	assert.strictEqual(ext.readUInt16BE(8), 0x001d)
	assert.strictEqual(ext.readUInt16BE(10), 0x0017)
})

test('supported_groups (10): useGrease=false omits GREASE', () => {
	const ext = CreateSupportedGroupsExtension(0xAA, [0x001d, 0x0017], { useGrease: false })
	// hdr(2) + extLen(2) + listLen(2) + entries(2*2=4)
	assert.strictEqual(ext.length, 10)
	assert.strictEqual(ext.readUInt16BE(6), 0x001d)
	assert.strictEqual(ext.readUInt16BE(8), 0x0017)
})

test('supported_versions (43): useGrease=true prepends GREASE codepoint', () => {
	const ext = CreateSupportedVersionsExtension(0xBB, [0x0304, 0x0303])
	// hdr(2) + extLen(2) + listLen(1) + entries(3*2=6)
	assert.strictEqual(ext.length, 11)
	assert.strictEqual(ext.readUInt16BE(5), 0xBBBB)
	assert.strictEqual(ext.readUInt16BE(7), 0x0304)
})

test('supported_versions (43): useGrease=false emits only the requested versions', () => {
	const ext = CreateSupportedVersionsExtension(0xBB, [0x0303], { useGrease: false })
	// hdr(2) + extLen(2) + listLen(1) + entries(1*2=2)
	assert.strictEqual(ext.length, 7)
	assert.strictEqual(ext.readUInt16BE(5), 0x0303)
})
