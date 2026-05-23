// ClientHelloInner / ClientHelloOuter construction for real ECH.
//
// The existing TLS builder knows how to serialize Chrome-shaped extensions, but real ECH
// needs an extra layer:
//   - build the true inner ClientHello
//   - encode/pad it per RFC 9849
//   - build the outer AAD with a zeroed payload placeholder
//   - seal the inner bytes and splice the final encrypted_client_hello extension back in
//
// Keeping that logic here lets the TCP and QUIC handshakes share one implementation.
const crypto = require('crypto')

const HKDF = require('../utils/hkdf')
const { CreateEncryptedClientHelloExtension } = require('../extensions')
const { setupBaseSender } = require('./ech-hpke')

const ECH_OUTER_EXTENSIONS_TYPE = 0xfd00
const ECH_EXTENSION_TYPE = 0xfe0d
const HELLO_RETRY_REQUEST_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex')
const AEAD_TAG_LENGTHS = {
	0x0001: 16,
}

async function buildECHOffer(options) {
	const config = options?.config
	if (!config || typeof config.configId !== 'number' || !Buffer.isBuffer(config.raw)) throw new TypeError('ECH config with configId and raw bytes is required')
	const innerHello = normalizeClientHello(options?.innerHello, 'innerHello')
	const outerHello = normalizeClientHello(options?.outerHello, 'outerHello')
	const outerExtensions = normalizeExtensionList(options?.outerExtensions, 'outerExtensions')
	const innerExtensions = normalizeExtensionList(options?.innerExtensions, 'innerExtensions')
	const outerInsertionIndex = normalizeInsertionIndex(options?.echExtensionIndex, outerExtensions.length, 'echExtensionIndex')
	const innerInsertionIndex = normalizeInsertionIndex(options?.innerEchExtensionIndex ?? outerInsertionIndex, innerExtensions.length, 'innerEchExtensionIndex')
	const compressionPlan = buildCompressionPlan(innerExtensions, outerExtensions, options?.compressExtensionTypes)
	const innerCompressed = applyCompressionPlan(innerExtensions, compressionPlan)
	const innerFinal = insertAt(innerCompressed, adjustInsertionIndex(innerInsertionIndex, compressionPlan), CreateEncryptedClientHelloExtension({ type: 'inner' }))
	const innerClientHello = serializeClientHello({
		legacyVersion: innerHello.legacyVersion,
		random: innerHello.random,
		sessionId: innerHello.sessionId,
		cipherSuites: innerHello.cipherSuites,
		compressionMethods: innerHello.compressionMethods,
		extensions: innerFinal,
	})
	const encodedInnerClientHello = serializeClientHello({
		legacyVersion: innerHello.legacyVersion,
		random: innerHello.random,
		sessionId: Buffer.alloc(0),
		cipherSuites: innerHello.cipherSuites,
		compressionMethods: innerHello.compressionMethods,
		extensions: innerFinal,
	})
	const encodedInner = encodeClientHelloInner(encodedInnerClientHello, innerExtensions, config.maximumNameLength || 0)
	const sender = await resolveSender(config, options)
	const tagLength = getPayloadTagLength(sender.aeadId)
	const placeholderExtension = CreateEncryptedClientHelloExtension({
		type: 'outer',
		cipherSuite: { kdfId: sender.kdfId, aeadId: sender.aeadId },
		configId: config.configId,
		enc: sender.enc,
		payload: Buffer.alloc(encodedInner.length + tagLength),
	})
	const outerAadExtensions = insertAt(outerExtensions, outerInsertionIndex, placeholderExtension)
	const outerClientHelloAAD = serializeClientHello({
		legacyVersion: outerHello.legacyVersion,
		random: outerHello.random,
		sessionId: outerHello.sessionId,
		cipherSuites: outerHello.cipherSuites,
		compressionMethods: outerHello.compressionMethods,
		extensions: outerAadExtensions,
	})
	const payload = Buffer.from(await sender.seal(encodedInner, outerClientHelloAAD))
	if (payload.length !== encodedInner.length + tagLength) throw new Error('ECH payload length mismatch')
	const extension = CreateEncryptedClientHelloExtension({
		type: 'outer',
		cipherSuite: { kdfId: sender.kdfId, aeadId: sender.aeadId },
		configId: config.configId,
		enc: sender.enc,
		payload,
	})
	const outerFinal = insertAt(outerExtensions, outerInsertionIndex, extension)
	const outerClientHello = serializeClientHello({
		legacyVersion: outerHello.legacyVersion,
		random: outerHello.random,
		sessionId: outerHello.sessionId,
		cipherSuites: outerHello.cipherSuites,
		compressionMethods: outerHello.compressionMethods,
		extensions: outerFinal,
	})
	return {
		extension,
		cipherSuite: { kdfId: sender.kdfId, aeadId: sender.aeadId },
		configId: config.configId,
		enc: Buffer.from(sender.enc),
		payload,
		innerRandom: Buffer.from(innerHello.random),
		innerClientHello,
		innerClientHelloHandshake: toHandshakeMessage(0x01, innerClientHello),
		encodedInnerClientHello,
		encodedInner,
		outerClientHelloAAD,
		outerClientHello,
		outerClientHelloHandshake: toHandshakeMessage(0x01, outerClientHello),
		compressExtensionTypes: compressionPlan.types.slice(),
	}
}

function encodeClientHelloInner(innerClientHello, originalInnerExtensions, maximumNameLength) {
	const sniLength = getServerNameLength(originalInnerExtensions)
	const maxNameLength = Math.max(0, maximumNameLength | 0)
	let paddingLength = sniLength == null ? maxNameLength + 9 : Math.max(0, maxNameLength - sniLength)
	const baseLength = innerClientHello.length + paddingLength
	paddingLength += 31 - ((baseLength - 1) % 32)
	return Buffer.concat([innerClientHello, Buffer.alloc(paddingLength)])
}

function computeECHAcceptanceConfirmation(options) {
	const clientHelloInnerRandom = asFixedBuffer(options?.clientHelloInnerRandom, 32, 'clientHelloInnerRandom')
	const transcriptHash = asBuffer(options?.transcriptHash, 'transcriptHash')
	const hashName = options?.hashName
	if (typeof hashName !== 'string' || hashName.length === 0) throw new TypeError('hashName is required')
	const label = options?.helloRetryRequest ? 'hrr ech accept confirmation' : 'ech accept confirmation'
	const secret = HKDF.Extract(hashName, Buffer.alloc(transcriptHash.length), clientHelloInnerRandom)
	return HKDF.ExpandLabel(secret, label, transcriptHash, 8, hashName, transcriptHash.length)
}

function confirmECHAcceptance(options) {
	const clientHelloInner = asBuffer(options?.clientHelloInner, 'clientHelloInner')
	const serverHello = asBuffer(options?.serverHello, 'serverHello')
	const hashName = options?.hashName
	if (typeof hashName !== 'string' || hashName.length === 0) throw new TypeError('hashName is required')
	const helloRetryRequest = options?.helloRetryRequest ?? isHelloRetryRequest(serverHello)
	const clientHelloInnerRandom = extractClientHelloRandom(clientHelloInner)
	const confirmation = helloRetryRequest ? extractHelloRetryRequestConfirmation(serverHello) : extractServerHelloConfirmation(serverHello)
	if (confirmation == null) return false
	const transcriptHash = crypto.createHash(hashName)
		.update(clientHelloInner)
		.update(zeroServerHelloConfirmation(serverHello, helloRetryRequest))
		.digest()
	const expected = computeECHAcceptanceConfirmation({
		clientHelloInnerRandom,
		transcriptHash,
		hashName,
		helloRetryRequest,
	})
	return confirmation.length === expected.length && crypto.timingSafeEqual(confirmation, expected)
}

function isHelloRetryRequest(serverHello) {
	const random = extractServerHelloRandom(asBuffer(serverHello, 'serverHello'))
	return HELLO_RETRY_REQUEST_RANDOM.equals(random)
}

function serializeClientHello({ legacyVersion, random, sessionId, cipherSuites, compressionMethods, extensions }) {
	const extList = Buffer.concat(extensions)
	const extLen = Buffer.alloc(2)
	extLen.writeUInt16BE(extList.length, 0)
	const sessionIdLength = Buffer.from([sessionId.length])
	const cipherSuitesLength = Buffer.alloc(2)
	cipherSuitesLength.writeUInt16BE(cipherSuites.length, 0)
	return Buffer.concat([
		legacyVersion,
		random,
		sessionIdLength,
		sessionId,
		cipherSuitesLength,
		cipherSuites,
		compressionMethods,
		extLen,
		extList,
	])
}

async function resolveSender(config, options) {
	if (options?.sender) return normalizeSender(options.sender)
	const info = Buffer.concat([Buffer.from('tls ech\0', 'ascii'), config.raw])
	return setupBaseSender(config, { info })
}

function normalizeSender(sender) {
	if (!sender || typeof sender.seal !== 'function') throw new TypeError('sender.seal() is required')
	if (typeof sender.kdfId !== 'number' || typeof sender.aeadId !== 'number') throw new TypeError('sender kdfId/aeadId are required')
	return {
		kdfId: sender.kdfId,
		aeadId: sender.aeadId,
		enc: asBuffer(sender.enc, 'sender.enc'),
		seal(plaintext, aad) {
			return sender.seal(plaintext, aad)
		},
	}
}

function buildCompressionPlan(innerExtensions, outerExtensions, requestedTypes) {
	const types = Array.isArray(requestedTypes) ? requestedTypes.slice() : []
	const seen = new Set()
	for (const type of types) {
		if (!Number.isInteger(type) || type < 0 || type > 0xffff) throw new TypeError('compressExtensionTypes must contain uint16 values')
		if (seen.has(type)) throw new Error(`duplicate compressed extension 0x${type.toString(16)}`)
		seen.add(type)
	}
	const innerTypes = innerExtensions.map(readExtensionType)
	const outerTypes = outerExtensions.map(readExtensionType)
	const positions = types.map((type) => {
		const innerIndex = innerTypes.indexOf(type)
		if (innerIndex === -1) throw new Error(`missing inner extension 0x${type.toString(16)} for ech_outer_extensions`)
		const outerIndex = outerTypes.indexOf(type)
		if (outerIndex === -1) throw new Error(`missing outer extension 0x${type.toString(16)} for ech_outer_extensions`)
		if (!innerExtensions[innerIndex].equals(outerExtensions[outerIndex])) {
			throw new Error(`compressed extension 0x${type.toString(16)} differs between inner and outer ClientHello`)
		}
		if (type === ECH_EXTENSION_TYPE) throw new Error('ech_outer_extensions cannot reference encrypted_client_hello')
		return { type, innerIndex, outerIndex }
	})
	positions.sort((a, b) => a.innerIndex - b.innerIndex)
	for (let i = 1; i < positions.length; i++) {
		if (positions[i].innerIndex !== positions[i - 1].innerIndex + 1) throw new Error('compressed inner extensions must be contiguous')
		if (positions[i].outerIndex <= positions[i - 1].outerIndex) throw new Error('compressed outer extensions must preserve relative order')
	}
	if (positions.length === 0) {
		return {
			types,
			firstInnerIndex: -1,
			lastInnerIndex: -1,
		}
	}
	return {
		types: positions.map((pos) => pos.type),
		firstInnerIndex: positions[0].innerIndex,
		lastInnerIndex: positions[positions.length - 1].innerIndex,
	}
}

function applyCompressionPlan(innerExtensions, compressionPlan) {
	if (!compressionPlan.types.length) return innerExtensions.slice()
	return [
		...innerExtensions.slice(0, compressionPlan.firstInnerIndex),
		createOuterExtensionsExtension(compressionPlan.types),
		...innerExtensions.slice(compressionPlan.lastInnerIndex + 1),
	]
}

function adjustInsertionIndex(index, compressionPlan) {
	if (!compressionPlan.types.length) return index
	if (index <= compressionPlan.firstInnerIndex) return index
	if (index > compressionPlan.lastInnerIndex) return index - (compressionPlan.types.length - 1)
	return compressionPlan.firstInnerIndex + 1
}

function createOuterExtensionsExtension(types) {
	const body = Buffer.alloc(1 + (types.length * 2))
	body[0] = types.length * 2
	for (let i = 0; i < types.length; i++) body.writeUInt16BE(types[i], 1 + (i * 2))
	const ext = Buffer.alloc(4)
	ext.writeUInt16BE(ECH_OUTER_EXTENSIONS_TYPE, 0)
	ext.writeUInt16BE(body.length, 2)
	return Buffer.concat([ext, body])
}

function insertAt(items, index, value) {
	return [...items.slice(0, index), value, ...items.slice(index)]
}

function normalizeClientHello(clientHello, label) {
	if (!clientHello || typeof clientHello !== 'object') throw new TypeError(`${label} is required`)
	return {
		legacyVersion: asFixedBuffer(clientHello.legacyVersion, 2, `${label}.legacyVersion`),
		random: asFixedBuffer(clientHello.random, 32, `${label}.random`),
		sessionId: asBuffer(clientHello.sessionId || Buffer.alloc(0), `${label}.sessionId`),
		cipherSuites: asBuffer(clientHello.cipherSuites, `${label}.cipherSuites`),
		compressionMethods: asBuffer(clientHello.compressionMethods, `${label}.compressionMethods`),
	}
}

function normalizeExtensionList(extensions, label) {
	if (!Array.isArray(extensions)) throw new TypeError(`${label} must be an array`)
	const out = []
	const seen = new Set()
	for (const ext of extensions) {
		const buf = asBuffer(ext, label)
		if (buf.length < 4) throw new Error(`${label} entries must contain an extension header`)
		const type = readExtensionType(buf)
		if (seen.has(type)) throw new Error(`duplicate extension 0x${type.toString(16)} in ${label}`)
		seen.add(type)
		out.push(buf)
	}
	return out
}

function normalizeInsertionIndex(value, length, label) {
	if (!Number.isInteger(value) || value < 0 || value > length) throw new RangeError(`${label} must be between 0 and ${length}`)
	return value
}

function readExtensionType(ext) {
	return ext.readUInt16BE(0)
}

function getServerNameLength(extensions) {
	const ext = extensions.find((value) => readExtensionType(value) === 0)
	if (!ext) return null
	const body = readExtensionBody(ext)
	if (body.length < 5) throw new Error('invalid server_name extension')
	const nameLength = body.readUInt16BE(3)
	if (body.length < 5 + nameLength) throw new Error('invalid server_name extension')
	return nameLength
}

function readExtensionBody(ext) {
	const length = ext.readUInt16BE(2)
	if (ext.length !== 4 + length) throw new Error(`invalid extension length for 0x${readExtensionType(ext).toString(16)}`)
	return ext.subarray(4)
}

function getPayloadTagLength(aeadId) {
	const tagLength = AEAD_TAG_LENGTHS[aeadId]
	if (!tagLength) throw new Error(`unsupported ECH AEAD 0x${aeadId.toString(16)}`)
	return tagLength
}

function toHandshakeMessage(type, body) {
	const len = Buffer.alloc(3)
	len.writeUIntBE(body.length, 0, 3)
	return Buffer.concat([Buffer.from([type]), len, body])
}

function extractClientHelloRandom(clientHelloInner) {
	if (clientHelloInner.length < 38) throw new Error('ClientHello is too short')
	return clientHelloInner.subarray(6, 38)
}

function extractServerHelloRandom(serverHello) {
	if (serverHello.length < 38) throw new Error('ServerHello is too short')
	return serverHello.subarray(6, 38)
}

function extractServerHelloConfirmation(serverHello) {
	const random = extractServerHelloRandom(serverHello)
	return random.subarray(random.length - 8)
}

function extractHelloRetryRequestConfirmation(serverHello) {
	const ext = findServerHelloExtension(serverHello, ECH_EXTENSION_TYPE)
	if (!ext) return null
	if (ext.length !== 8) throw new Error('invalid ECH HelloRetryRequest confirmation length')
	return ext.data
}

function zeroServerHelloConfirmation(serverHello, helloRetryRequest) {
	const copy = Buffer.from(serverHello)
	if (!helloRetryRequest) {
		copy.fill(0, 30, 38)
		return copy
	}
	const ext = findServerHelloExtension(copy, ECH_EXTENSION_TYPE)
	if (!ext) return copy
	if (ext.length !== 8) throw new Error('invalid ECH HelloRetryRequest confirmation length')
	ext.data.fill(0)
	return copy
}

function findServerHelloExtension(serverHello, wantedType) {
	let offset = 4
	if (serverHello.length < offset + 2 + 32 + 1 + 2 + 1 + 2) throw new Error('ServerHello is too short')
	offset += 2 + 32
	const sessionIdLength = serverHello[offset++]
	offset += sessionIdLength + 2 + 1
	const extensionsLength = serverHello.readUInt16BE(offset); offset += 2
	const end = offset + extensionsLength
	if (end > serverHello.length) throw new Error('ServerHello extensions are truncated')
	while (offset + 4 <= end) {
		const type = serverHello.readUInt16BE(offset); offset += 2
		const length = serverHello.readUInt16BE(offset); offset += 2
		const dataEnd = offset + length
		if (dataEnd > end) throw new Error('ServerHello extension is truncated')
		if (type === wantedType) {
			return {
				data: serverHello.subarray(offset, dataEnd),
				length,
			}
		}
		offset = dataEnd
	}
	if (offset !== end) throw new Error('ServerHello extensions are malformed')
	return null
}

function asBuffer(value, label) {
	if (Buffer.isBuffer(value)) return value
	if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
	throw new TypeError(`${label} must be a Buffer`)
}

function asFixedBuffer(value, length, label) {
	const buf = asBuffer(value, label)
	if (buf.length !== length) throw new RangeError(`${label} must be ${length} bytes`)
	return buf
}

module.exports = {
	buildECHOffer,
	computeECHAcceptanceConfirmation,
	confirmECHAcceptance,
	isHelloRetryRequest,
}
