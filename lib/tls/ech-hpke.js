// Thin HPKE adapter for ECH.
//
// The heavy lifting comes from the external `hpke` package; this file keeps the rest of
// the codebase insulated from that API and centralizes the "only use what the published
// ECHConfig actually offered" checks.
//
// We load the dependency lazily because the package is ESM-only while this repo stays
// CommonJS.
const { SUPPORTED_KEM_IDS, SUPPORTED_KDF_IDS, SUPPORTED_AEAD_IDS } = require('./ech-config')

let hpkeModulePromise = null

function loadHpke() {
	if (!hpkeModulePromise) hpkeModulePromise = import('hpke')
	return hpkeModulePromise
}

async function createSuite(kemId, kdfId, aeadId) {
	const hpke = await loadHpke()
	return new hpke.CipherSuite(
		resolveKem(hpke, kemId),
		resolveKdf(hpke, kdfId),
		resolveAead(hpke, aeadId),
	)
}

function ensureCipherSuiteOffered(config, kdfId, aeadId) {
	if (!(config?.cipherSuites || []).some((cipherSuite) => cipherSuite.kdfId === kdfId && cipherSuite.aeadId === aeadId)) {
		throw new Error(`ECH cipher suite 0x${kdfId.toString(16)}/0x${aeadId.toString(16)} not offered by config`)
	}
}

async function deserializePublicKey(config, publicKey = config?.publicKey, options = {}) {
	if (!config || typeof config.kemId !== 'number') throw new TypeError('ECH config with kemId is required')
	const kdfId = options.kdfId ?? config?.kdfId ?? selectSupportedKdfId(config)
	const aeadId = options.aeadId ?? config?.aeadId ?? selectSupportedAeadId(config)
	if (typeof kdfId !== 'number' || typeof aeadId !== 'number') throw new Error('supported ECH KDF/AEAD is required')
	ensureCipherSuiteOffered(config, kdfId, aeadId)
	const keyBytes = asUint8Array(publicKey, 'ECH public key')
	const suite = await createSuite(config.kemId, kdfId, aeadId)
	return suite.DeserializePublicKey(keyBytes)
}

async function setupBaseSender(config, options = {}) {
	const kemId = config?.kemId
	const kdfId = options.kdfId ?? config?.kdfId ?? selectSupportedKdfId(config)
	const aeadId = options.aeadId ?? config?.aeadId ?? selectSupportedAeadId(config)
	if (typeof kemId !== 'number' || typeof kdfId !== 'number' || typeof aeadId !== 'number') {
		throw new Error('supported ECH KEM/KDF/AEAD is required')
	}
	ensureCipherSuiteOffered(config, kdfId, aeadId)
	const suite = await createSuite(kemId, kdfId, aeadId)
	const recipientPublicKey = await suite.DeserializePublicKey(asUint8Array(options.publicKey || config.publicKey, 'ECH public key'))
	const { encapsulatedSecret, ctx } = await suite.SetupSender(recipientPublicKey, {
		info: asOptionalUint8Array(options.info, 'ECH info'),
	})
	return {
		kemId,
		kdfId,
		aeadId,
		enc: Buffer.from(encapsulatedSecret),
		seal(plaintext, aad) {
			return sealWithContext(ctx, plaintext, aad)
		},
	}
}

async function sealECH(config, options = {}) {
	const sender = await setupBaseSender(config, options)
	return {
		kemId: sender.kemId,
		kdfId: sender.kdfId,
		aeadId: sender.aeadId,
		enc: sender.enc,
		payload: await sender.seal(options.plaintext, options.aad),
		context: sender,
	}
}

function selectSupportedKdfId(config) {
	for (const cipherSuite of config?.cipherSuites || []) {
		if (SUPPORTED_KDF_IDS.has(cipherSuite.kdfId) && SUPPORTED_AEAD_IDS.has(cipherSuite.aeadId)) return cipherSuite.kdfId
	}
	return null
}

function selectSupportedAeadId(config) {
	for (const cipherSuite of config?.cipherSuites || []) {
		if (SUPPORTED_KDF_IDS.has(cipherSuite.kdfId) && SUPPORTED_AEAD_IDS.has(cipherSuite.aeadId)) return cipherSuite.aeadId
	}
	return null
}

function resolveKem(hpke, kemId) {
	if (!SUPPORTED_KEM_IDS.has(kemId)) throw new Error(`unsupported ECH KEM 0x${kemId.toString(16)}`)
	if (kemId === 0x0020) return hpke.KEM_DHKEM_X25519_HKDF_SHA256
	throw new Error(`unsupported ECH KEM 0x${kemId.toString(16)}`)
}

function resolveKdf(hpke, kdfId) {
	if (!SUPPORTED_KDF_IDS.has(kdfId)) throw new Error(`unsupported ECH KDF 0x${kdfId.toString(16)}`)
	if (kdfId === 0x0001) return hpke.KDF_HKDF_SHA256
	throw new Error(`unsupported ECH KDF 0x${kdfId.toString(16)}`)
}

function resolveAead(hpke, aeadId) {
	if (!SUPPORTED_AEAD_IDS.has(aeadId)) throw new Error(`unsupported ECH AEAD 0x${aeadId.toString(16)}`)
	if (aeadId === 0x0001) return hpke.AEAD_AES_128_GCM
	throw new Error(`unsupported ECH AEAD 0x${aeadId.toString(16)}`)
}

async function sealWithContext(ctx, plaintext, aad) {
	const ciphertext = await ctx.Seal(
		asUint8Array(plaintext, 'ECH plaintext'),
		asOptionalUint8Array(aad, 'ECH AAD'),
	)
	return Buffer.from(ciphertext)
}

function asUint8Array(value, label) {
	if (!value || typeof value.length !== 'number') throw new TypeError(`${label} must be bytes`)
	if (value instanceof Uint8Array || Buffer.isBuffer(value)) return value
	throw new TypeError(`${label} must be bytes`)
}

function asOptionalUint8Array(value, label) {
	if (value == null) return undefined
	return asUint8Array(value, label)
}

module.exports = {
	loadHpke,
	createSuite,
	deserializePublicKey,
	setupBaseSender,
	sealECH,
}
