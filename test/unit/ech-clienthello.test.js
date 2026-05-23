const test = require('node:test')
const assert = require('node:assert')

const {
	CreateALPNExtension,
	CreateSNIExtension,
	CreateSupportedVersionsExtension,
} = require('../../lib/extensions')
const { buildECHOffer } = require('../../lib/tls/ech-clienthello')

const ECH_EXTENSION_TYPE = 0xfe0d
const ECH_OUTER_EXTENSIONS_TYPE = 0xfd00

function makeConfig() {
	return {
		configId: 7,
		maximumNameLength: 18,
		raw: Buffer.from('fe0d000401020304', 'hex'),
	}
}

function makeHello(randomHex) {
	return {
		legacyVersion: Buffer.from([0x03, 0x03]),
		random: Buffer.from(randomHex, 'hex'),
		sessionId: Buffer.from('11223344', 'hex'),
		cipherSuites: Buffer.from('13011302', 'hex'),
		compressionMethods: Buffer.from([0x01, 0x00]),
	}
}

function parseClientHelloExtensions(clientHello) {
	let offset = 0
	offset += 2 + 32
	const sessionIdLength = clientHello[offset++]
	offset += sessionIdLength
	const cipherSuitesLength = clientHello.readUInt16BE(offset); offset += 2 + cipherSuitesLength
	const compressionMethodsLength = clientHello[offset++]
	offset += compressionMethodsLength
	const extensionsLength = clientHello.readUInt16BE(offset); offset += 2
	const end = offset + extensionsLength
	const extensions = []
	while (offset + 4 <= end) {
		const type = clientHello.readUInt16BE(offset); offset += 2
		const length = clientHello.readUInt16BE(offset); offset += 2
		const data = clientHello.subarray(offset, offset + length)
		offset += length
		extensions.push({ type, data })
	}
	assert.strictEqual(offset, end)
	return extensions
}

function readOuterPayload(extensionData) {
	assert.strictEqual(extensionData[0], 0x00)
	const encLength = extensionData.readUInt16BE(6)
	const payloadOffset = 8 + encLength
	const payloadLength = extensionData.readUInt16BE(payloadOffset)
	return extensionData.subarray(payloadOffset + 2, payloadOffset + 2 + payloadLength)
}

test('buildECHOffer compresses inner extensions and zeroes the outer AAD payload', async () => {
	const captured = {}
	const sender = {
		kdfId: 0x0001,
		aeadId: 0x0001,
		enc: Buffer.from('01020304', 'hex'),
		async seal(plaintext, aad) {
			captured.plaintext = Buffer.from(plaintext)
			captured.aad = Buffer.from(aad)
			return Buffer.concat([Buffer.alloc(plaintext.length, 0x5a), Buffer.alloc(16, 0xa5)])
		},
	}
	const offer = await buildECHOffer({
		config: makeConfig(),
		innerHello: makeHello('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
		outerHello: makeHello('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'),
		innerExtensions: [
			CreateSNIExtension('secret.example'),
			CreateALPNExtension(['h2']),
			CreateSupportedVersionsExtension(0x0a, [0x0304], { useGrease: false }),
		],
		outerExtensions: [
			CreateSNIExtension('public.example'),
			CreateALPNExtension(['h2']),
			CreateSupportedVersionsExtension(0x0a, [0x0304, 0x0303], { useGrease: false }),
		],
		echExtensionIndex: 1,
		compressExtensionTypes: [16],
		sender,
	})

	const innerExtensions = parseClientHelloExtensions(offer.innerClientHello)
	assert.deepStrictEqual(innerExtensions.map((ext) => ext.type), [0, ECH_EXTENSION_TYPE, ECH_OUTER_EXTENSIONS_TYPE, 43])
	assert.deepStrictEqual(innerExtensions[1].data, Buffer.from([0x01]))
	assert.deepStrictEqual(innerExtensions[2].data, Buffer.from([0x02, 0x00, 0x10]))
	assert.strictEqual(offer.encodedInner.length % 32, 0)
	assert.deepStrictEqual(offer.encodedInner.subarray(offer.encodedInnerClientHello.length), Buffer.alloc(offer.encodedInner.length - offer.encodedInnerClientHello.length))
	assert.deepStrictEqual(captured.plaintext, offer.encodedInner)

	const aadExtensions = parseClientHelloExtensions(captured.aad)
	const aadEch = aadExtensions.find((ext) => ext.type === ECH_EXTENSION_TYPE)
	assert.ok(aadEch)
	assert.deepStrictEqual(readOuterPayload(aadEch.data), Buffer.alloc(offer.payload.length))

	const outerExtensions = parseClientHelloExtensions(offer.outerClientHello)
	const outerEch = outerExtensions.find((ext) => ext.type === ECH_EXTENSION_TYPE)
	assert.ok(outerEch)
	assert.deepStrictEqual(readOuterPayload(outerEch.data), offer.payload)
})

test('buildECHOffer rejects non-contiguous compressed inner extensions', async () => {
	await assert.rejects(() => buildECHOffer({
		config: makeConfig(),
		innerHello: makeHello('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
		outerHello: makeHello('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'),
		innerExtensions: [
			CreateSNIExtension('public.example'),
			CreateSupportedVersionsExtension(0x0a, [0x0304], { useGrease: false }),
			CreateALPNExtension(['h2']),
		],
		outerExtensions: [
			CreateSNIExtension('public.example'),
			CreateSupportedVersionsExtension(0x0a, [0x0304, 0x0303], { useGrease: false }),
			CreateALPNExtension(['h2']),
		],
		echExtensionIndex: 1,
		compressExtensionTypes: [0, 16],
		sender: {
			kdfId: 0x0001,
			aeadId: 0x0001,
			enc: Buffer.from('00', 'hex'),
			async seal() {
				return Buffer.alloc(17)
			},
		},
	}), /contiguous/)
})

test('buildECHOffer treats maximum_name_length as a padding hint, not a hard cap', async () => {
	const offer = await buildECHOffer({
		config: {
			...makeConfig(),
			maximumNameLength: 0,
		},
		innerHello: makeHello('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'),
		outerHello: makeHello('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100'),
		innerExtensions: [
			CreateSNIExtension('secret.example'),
			CreateALPNExtension(['h2']),
			CreateSupportedVersionsExtension(0x0a, [0x0304], { useGrease: false }),
		],
		outerExtensions: [
			CreateSNIExtension('public.example'),
			CreateALPNExtension(['h2']),
			CreateSupportedVersionsExtension(0x0a, [0x0304, 0x0303], { useGrease: false }),
		],
		echExtensionIndex: 1,
		compressExtensionTypes: [],
		sender: {
			kdfId: 0x0001,
			aeadId: 0x0001,
			enc: Buffer.from('01020304', 'hex'),
			async seal(plaintext) { return Buffer.alloc(plaintext.length + 16) },
		},
	})
	assert.ok(offer.encodedInner.length >= offer.encodedInnerClientHello.length)
	assert.strictEqual(offer.encodedInner.length % 32, 0)
})
