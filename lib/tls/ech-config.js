// RFC 9849 ECHConfigList parsing and local support policy.
//
// This module does two jobs:
//   - parse the DNS-published bytes into stable JS objects with copied buffers
//   - select the first config/cipher suite this client can actually use
//
// Unsupported versions remain opaque so callers can preserve raw retry_configs while
// still ignoring entries they do not understand.
const SUPPORTED_ECH_VERSION = 0xfe0d
const SUPPORTED_KEM_IDS = new Set([0x0020])
const SUPPORTED_KDF_IDS = new Set([0x0001])
const SUPPORTED_AEAD_IDS = new Set([0x0001])

function parseECHConfigList(buf) {
	const input = asBuffer(buf, 'ECHConfigList')
	if (input.length < 2) throw new Error('truncated ECHConfigList')
	const listLen = input.readUInt16BE(0)
	if (listLen !== input.length - 2) throw new Error('invalid ECHConfigList length')
	if (listLen === 0) throw new Error('ECHConfigList must contain at least one config')
	const configs = []
	let offset = 2
	while (offset < input.length) {
		if (offset + 4 > input.length) throw new Error('truncated ECHConfig')
		const rawStart = offset
		const version = input.readUInt16BE(offset); offset += 2
		const configLen = input.readUInt16BE(offset); offset += 2
		const rawEnd = offset + configLen
		if (rawEnd > input.length) throw new Error('truncated ECHConfig contents')
		const raw = input.subarray(rawStart, rawEnd)
		const contents = input.subarray(offset, rawEnd)
		configs.push(parseECHConfig(version, raw, contents))
		offset = rawEnd
	}
	return configs
}

function parseRetryConfigs(buf) {
	return parseECHConfigList(buf)
}

function parseECHConfig(version, raw, contents) {
	const config = {
		version,
		raw: Buffer.from(raw),
		contents: Buffer.from(contents),
		supportedVersion: version === SUPPORTED_ECH_VERSION,
	}
	if (version !== SUPPORTED_ECH_VERSION) return config
	let offset = 0
	if (contents.length < 8) throw new Error('truncated ECHConfig contents')
	config.configId = contents[offset++]
	config.kemId = contents.readUInt16BE(offset); offset += 2
	config.publicKey = Buffer.from(readOpaque16(contents, offset, 'ECHConfig public_key'))
	if (config.publicKey.length === 0) throw new Error('invalid ECHConfig public_key')
	offset += 2 + config.publicKey.length
	config.cipherSuites = parseCipherSuites(contents, offset)
	offset += 2 + (config.cipherSuites.length * 4)
	if (offset >= contents.length) throw new Error('truncated ECHConfig maximum_name_length')
	config.maximumNameLength = contents[offset++]
	const publicNameBytes = readOpaque8(contents, offset, 'ECHConfig public_name')
	offset += 1 + publicNameBytes.length
	config.publicName = parsePublicName(publicNameBytes)
	config.publicNameBytes = Buffer.from(publicNameBytes)
	config.extensions = Buffer.from(readOpaque16(contents, offset, 'ECHConfig extensions'))
	offset += 2 + config.extensions.length
	config.parsedExtensions = parseConfigExtensions(config.extensions)
	config.hasUnsupportedExtensions = config.parsedExtensions.length > 0
	if (offset !== contents.length) throw new Error('invalid ECHConfig trailing bytes')
	return config
}

function parseCipherSuites(contents, offset) {
	const body = readOpaque16(contents, offset, 'ECHConfig cipher_suites')
	if (body.length === 0 || (body.length % 4) !== 0) throw new Error('invalid ECHConfig cipher_suites')
	const cipherSuites = []
	for (let i = 0; i < body.length; i += 4) {
		cipherSuites.push({
			kdfId: body.readUInt16BE(i),
			aeadId: body.readUInt16BE(i + 2),
		})
	}
	return cipherSuites
}

function parseConfigExtensions(body) {
	const extensions = []
	const seen = new Set()
	for (let offset = 0; offset < body.length;) {
		if (offset + 4 > body.length) throw new Error('truncated ECHConfig extensions')
		const type = body.readUInt16BE(offset)
		const data = readOpaque16(body, offset + 2, 'ECHConfig extension_data')
		if (seen.has(type)) throw new Error(`duplicate ECHConfig extension 0x${type.toString(16)}`)
		seen.add(type)
		extensions.push({ type, data: Buffer.from(data) })
		offset += 4 + data.length
	}
	return extensions
}

function parsePublicName(bytes) {
	if (bytes.length === 0) throw new Error('invalid ECHConfig public_name')
	for (const byte of bytes) {
		if (byte < 0x21 || byte > 0x7e) throw new Error('invalid ECHConfig public_name')
	}
	const name = bytes.toString('ascii')
	if (name.startsWith('.') || name.endsWith('.')) throw new Error('invalid ECHConfig public_name')
	const labels = name.split('.')
	for (const label of labels) {
		if (!label || label.length > 63) throw new Error('invalid ECHConfig public_name')
		if (label.startsWith('-') || label.endsWith('-')) throw new Error('invalid ECHConfig public_name')
		if (!/^[A-Za-z0-9-]+$/.test(label)) throw new Error('invalid ECHConfig public_name')
	}
	return name.toLowerCase()
}

function selectECHConfig(configs) {
	for (const config of configs) {
		if (config.version !== SUPPORTED_ECH_VERSION) continue
		if (config.hasUnsupportedExtensions) continue
		if (!SUPPORTED_KEM_IDS.has(config.kemId)) continue
		if (!selectECHCipherSuite(config)) continue
		return config
	}
	return null
}

function selectECHCipherSuite(config) {
	for (const cipherSuite of config.cipherSuites || []) {
		if (!SUPPORTED_KDF_IDS.has(cipherSuite.kdfId)) continue
		if (!SUPPORTED_AEAD_IDS.has(cipherSuite.aeadId)) continue
		return cipherSuite
	}
	return null
}

function readOpaque8(buf, offset, label) {
	if (offset >= buf.length) throw new Error(`truncated ${label}`)
	const length = buf[offset]
	const start = offset + 1
	const end = start + length
	if (end > buf.length) throw new Error(`truncated ${label}`)
	return buf.subarray(start, end)
}

function readOpaque16(buf, offset, label) {
	if (offset + 2 > buf.length) throw new Error(`truncated ${label}`)
	const length = buf.readUInt16BE(offset)
	const start = offset + 2
	const end = start + length
	if (end > buf.length) throw new Error(`truncated ${label}`)
	return buf.subarray(start, end)
}

function asBuffer(buf, label) {
	if (Buffer.isBuffer(buf)) return buf
	if (buf instanceof Uint8Array) return Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)
	throw new TypeError(`${label} must be a Buffer`)
}

module.exports = {
	SUPPORTED_ECH_VERSION,
	SUPPORTED_KEM_IDS,
	SUPPORTED_KDF_IDS,
	SUPPORTED_AEAD_IDS,
	parseECHConfigList,
	parseRetryConfigs,
	selectECHConfig,
	selectECHCipherSuite,
}
