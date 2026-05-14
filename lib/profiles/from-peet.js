// Build a hellojs profile by pasting a peet.ws (https://tls.peet.ws/api/all) response.
//
//   const profiles = require('@conorre/hellojs').profiles
//   const json = JSON.parse(fs.readFileSync('./captured.json', 'utf8'))
//   profiles.register('chrome148-mac', profiles.fromPeet(json))
//   request({ url: '...', profile: 'chrome148-mac' })
//
// What gets mirrored (the structural fingerprint — JA3, JA4, akamai_fingerprint):
//   - Cipher list (order + GREASE placement)
//   - Extension order (server_name moved to end, ECH treated as GREASE)
//   - supported_groups (+ GREASE positions)
//   - supported_versions (+ GREASE)
//   - signature_algorithms order
//   - key_share group selection
//   - ALPN order
//   - ALPS protocols + extension type (44CD vs 4469)
//   - compress_certificate algorithm list
//   - HTTP/2 SETTINGS (and their insertion order)
//   - HTTP/2 WINDOW_UPDATE increment
//   - HTTP/2 HEADERS priority flag + values
//   - Pseudo-header order
//   - Default request headers + their order
//   - User-Agent
//
// What is NOT mirrored (these MUST rotate per-connection anyway, otherwise the fingerprint
// would be a constant value and detectable by exact byte match):
//   - Specific GREASE codepoints (Chrome picks fresh ones each handshake)
//   - client_random, session_id
//   - key_share key bytes
//   - ECH config bytes (peet.ws shows the SUCCESSFUL config from that handshake — pasting it
//     into another connection would attempt to use someone else's key. We send a GREASE ECH
//     instead, which matches Chrome's behavior when DNS HTTPS records don't advertise ECH.)
//   - session_ticket extension data (empty in CH1)
//
// What we can verify: paste the JSON, build the profile, run a request, and the resulting
// JA4 / JA3 / akamai_fingerprint hashes will match the input.

const { CIPHERS } = require('../utils/config')

// Build a name → numeric code lookup for ciphers. peet.ws prints names like
// "TLS_AES_128_GCM_SHA256" and hex like "(0x1a1a)".
const CIPHER_BY_NAME = {}
for (const [name, code] of Object.entries(CIPHERS)) CIPHER_BY_NAME[name] = code

// IANA TLS extension name → ID (https://www.iana.org/assignments/tls-extensiontype-values/).
// peet.ws annotates them like "supported_groups (10)" — we use the trailing number when present.
const EXTENSION_NAME_TO_ID = {
	server_name: 0,
	status_request: 5,
	supported_groups: 10,
	ec_point_formats: 11,
	signature_algorithms: 13,
	application_layer_protocol_negotiation: 16,
	signed_certificate_timestamp: 18,
	padding: 21,
	extended_master_secret: 23,
	compress_certificate: 27,
	session_ticket: 35,
	pre_shared_key: 41,
	supported_versions: 43,
	psk_key_exchange_modes: 45,
	key_share: 51,
	application_settings: 17613,         // 0x44cd (ALPS v1)
	application_settings_v2: 17517,      // 0x446d (ALPS v2; if ever seen)
	extensionEncryptedClientHello: 65037, // 0xfe0d
	extensionRenegotiationInfo: 65281,   // 0xff01
}

// signature_algorithms (RFC 8446 §4.2.3.1)
const SIGALG_BY_NAME = {
	ecdsa_secp256r1_sha256: 0x0403,
	ecdsa_secp384r1_sha384: 0x0503,
	ecdsa_secp521r1_sha512: 0x0603,
	rsa_pss_rsae_sha256:    0x0804,
	rsa_pss_rsae_sha384:    0x0805,
	rsa_pss_rsae_sha512:    0x0806,
	rsa_pkcs1_sha256:       0x0401,
	rsa_pkcs1_sha384:       0x0501,
	rsa_pkcs1_sha512:       0x0601,
	rsa_pkcs1_sha1:         0x0201,
	ed25519:                0x0807,
	ed448:                  0x0808,
}

// supported_groups (RFC 8446)
const GROUP_BY_NAME = {
	'P-256':                 0x0017,
	'P-384':                 0x0018,
	'P-521':                 0x0019,
	'X25519':                0x001d,
	'X448':                  0x001e,
	'X25519MLKEM768':        0x11ec,
	'X25519Kyber768':        0x6399,    // legacy hybrid
	'ffdhe2048':             0x0100,
	'secp256r1':             0x0017,
	'secp384r1':             0x0018,
	'secp521r1':             0x0019,
}

// cert-compression algorithm names per RFC 8879
const CERT_COMPRESS_BY_NAME = {
	zlib:   1,
	brotli: 2,
	zstd:   3,
}

// PSK key-exchange-mode names → numeric (RFC 8446 §4.2.9)
const PSK_KEM_BY_NAME = {
	psk_ke:     0,
	psk_dhe_ke: 1,
}

// Helpers for parsing peet.ws's annotated strings:
//   "TLS_AES_128_GCM_SHA256"
//   "TLS_GREASE (0x4A4A)"
//   "X25519MLKEM768 (4588)"
//   "supported_groups (10)"
//   "extensionEncryptedClientHello (boringssl) (65037)"

function isGreaseLabel(label) {
	return /^TLS_GREASE\b|\bGREASE\b/i.test(label)
}

// Parse the trailing "(0x..)" or "(N)" from a label. Returns null when nothing parses.
function extractHex(label) {
	const m = label.match(/\(0x([0-9a-fA-F]+)\)/)
	if (m) return parseInt(m[1], 16)
	return null
}
function extractNum(label) {
	const m = label.match(/\((\d+)\)$/) || label.match(/\((\d+)\)\s*$/)
	if (m) return parseInt(m[1], 10)
	return null
}

function cipherFromLabel(label) {
	if (isGreaseLabel(label)) return { grease: true }
	const code = label.replace(/\s*\(.*$/, '').trim()
	if (CIPHER_BY_NAME[code] != null) return { code: CIPHER_BY_NAME[code] }
	const hex = extractHex(label) ?? extractNum(label)
	if (hex != null) return { code: hex }
	throw new Error(`fromPeet: unknown cipher ${JSON.stringify(label)}`)
}

function groupFromLabel(label) {
	if (isGreaseLabel(label)) return { grease: true }
	const name = label.replace(/\s*\(.*$/, '').trim()
	if (GROUP_BY_NAME[name] != null) return { code: GROUP_BY_NAME[name] }
	const num = extractNum(label) ?? extractHex(label)
	if (num != null) return { code: num }
	throw new Error(`fromPeet: unknown group ${JSON.stringify(label)}`)
}

function versionFromLabel(label) {
	if (isGreaseLabel(label)) return { grease: true }
	const map = { 'TLS 1.3': 0x0304, 'TLS 1.2': 0x0303, 'TLS 1.1': 0x0302, 'TLS 1.0': 0x0301 }
	if (map[label.trim()] != null) return { code: map[label.trim()] }
	const num = extractNum(label) ?? extractHex(label)
	if (num != null) return { code: num }
	throw new Error(`fromPeet: unknown TLS version ${JSON.stringify(label)}`)
}

function sigalgFromLabel(label) {
	if (SIGALG_BY_NAME[label] != null) return SIGALG_BY_NAME[label]
	const num = extractNum(label) ?? extractHex(label)
	if (num != null) return num
	throw new Error(`fromPeet: unknown signature_algorithm ${JSON.stringify(label)}`)
}

function extensionIdFromLabel(label) {
	// "supported_groups (10)" → 10. "TLS_GREASE (0x6a6a)" → mark grease.
	if (isGreaseLabel(label)) return { grease: true }
	// peet labels the extension by name + paren'd number. Take the number if present.
	const num = extractNum(label) ?? extractHex(label)
	if (num != null) return { id: num }
	// Fallback to name lookup.
	const name = label.replace(/\s*\(.*$/, '').trim()
	if (EXTENSION_NAME_TO_ID[name] != null) return { id: EXTENSION_NAME_TO_ID[name] }
	throw new Error(`fromPeet: unknown extension ${JSON.stringify(label)}`)
}

function fromPeet(json, opts = {}) {
	if (!json || !json.tls || !json.http2) {
		throw new Error('fromPeet: input does not look like a peet.ws response (missing tls / http2)')
	}

	// ---- TLS ciphers (order + GREASE positions) ----
	const cipherCodes = []
	for (const c of json.tls.ciphers) {
		const r = cipherFromLabel(c)
		if (!r.grease) cipherCodes.push(r.code)
	}
	// Peet always shows GREASE in position 0 (Chrome behaviour). We treat GREASE as a runtime
	// flag and rely on our existing GREASE-injection logic to add one fresh code at position 0.

	// ---- Extensions ----
	const extensions = json.tls.extensions || []
	const extensionOrder = []      // [{id} | {grease:true}] preserving the wire order seen
	for (const ext of extensions) {
		const r = extensionIdFromLabel(ext.name)
		extensionOrder.push(r)
	}

	// Lookup helpers for specific extensions:
	const findExt = (idOrPredicate) =>
		extensions.find(e => {
			const r = extensionIdFromLabel(e.name)
			if (r.grease) return false
			return typeof idOrPredicate === 'function' ? idOrPredicate(r.id, e) : r.id === idOrPredicate
		})

	// supported_groups (10)
	const groupsExt = findExt(10)
	if (!groupsExt) throw new Error('fromPeet: supported_groups extension missing from input')
	const supportedGroups = []
	for (const g of groupsExt.supported_groups || []) {
		const r = groupFromLabel(g)
		if (!r.grease) supportedGroups.push(r.code)
	}

	// ALPN (16)
	const alpnExt = findExt(16)
	const alpn = alpnExt ? [...(alpnExt.protocols || [])] : ['h2', 'http/1.1']

	// supported_versions (43)
	const versionsExt = findExt(43)
	const supportedVersions = []
	if (versionsExt) {
		for (const v of versionsExt.versions || []) {
			const r = versionFromLabel(v)
			if (!r.grease) supportedVersions.push(r.code)
		}
	}

	// signature_algorithms (13)
	const sigExt = findExt(13)
	const signatureAlgorithms = []
	if (sigExt) for (const s of sigExt.signature_algorithms || []) signatureAlgorithms.push(sigalgFromLabel(s))

	// psk_key_exchange_modes (45)
	const pskExt = findExt(45)
	let pskKemModes = [1] // psk_dhe_ke default
	if (pskExt && pskExt.PSK_Key_Exchange_Mode) {
		const m = pskExt.PSK_Key_Exchange_Mode.match(/\((\d+)\)/)
		if (m) pskKemModes = [parseInt(m[1], 10)]
	}

	// key_share (51) — peet shows the offered groups; ignore the random key bytes.
	const ksExt = findExt(51)
	const keyShareGroups = []
	if (ksExt && Array.isArray(ksExt.shared_keys)) {
		for (const entry of ksExt.shared_keys) {
			const label = Object.keys(entry)[0]
			const r = groupFromLabel(label)
			if (!r.grease) keyShareGroups.push(r.code)
		}
	} else {
		// Fallback: send key_share for the first two non-GREASE supported groups.
		keyShareGroups.push(...supportedGroups.slice(0, 2))
	}

	// ALPS — peet shows it under the trailing "(17613)" or as "application_settings".
	const alpsExt = findExt((id) => id === 17613 || id === 17517)
	const alpsExtensionType = alpsExt ? (extractNum(alpsExt.name) ?? extractHex(alpsExt.name) ?? 17613) : null
	const alpsProtocols = alpsExt ? [...(alpsExt.protocols || ['h2'])] : null

	// compress_certificate (27)
	const ccExt = findExt(27)
	const certCompressionAlgorithms = []
	if (ccExt) for (const a of ccExt.algorithms || []) {
		const aname = a.replace(/\s*\(.*$/, '').trim()
		const code = CERT_COMPRESS_BY_NAME[aname] ?? extractNum(a) ?? extractHex(a)
		if (code != null) certCompressionAlgorithms.push(code)
	}

	// padding (21) — Safari emits this with a captured body length; Chrome 147 omits it.
	const padExt = findExt(21)
	const paddingLength = padExt ? (padExt.padding_data_length ?? 0) : null

	// ---- HTTP/2 ----
	const h2 = json.http2
	const sentSettings = (h2.sent_frames || []).find(f => f.frame_type === 'SETTINGS')
	const settings = {}
	if (sentSettings) {
		for (const s of sentSettings.settings || []) {
			const [name, val] = s.split('=').map(x => x.trim())
			const v = parseInt(val, 10)
			if (name === 'HEADER_TABLE_SIZE') settings.headerTableSize = v
			else if (name === 'ENABLE_PUSH') settings.enablePush = v !== 0
			else if (name === 'INITIAL_WINDOW_SIZE') settings.initialWindowSize = v
			else if (name === 'MAX_HEADER_LIST_SIZE') settings.maxHeaderListSize = v
			else if (name === 'MAX_CONCURRENT_STREAMS') settings.maxConcurrentStreams = v
			else if (name === 'MAX_FRAME_SIZE') settings.maxFrameSize = v
			else if (name === 'NO_RFC7540_PRIORITIES') settings.noRfc7540Priorities = v
		}
	}
	const winFrame = (h2.sent_frames || []).find(f => f.frame_type === 'WINDOW_UPDATE')
	const windowUpdateIncrement = winFrame ? winFrame.increment : 15663105

	const headersFrame = (h2.sent_frames || []).find(f => f.frame_type === 'HEADERS')
	const sendPriorityFrame = headersFrame ? (headersFrame.flags || []).some(f => f.includes('Priority')) : false
	const priority = headersFrame && headersFrame.priority
		? { weight: headersFrame.priority.weight, exclusive: !!headersFrame.priority.exclusive, parent: headersFrame.priority.depends_on || 0 }
		: { weight: 256, exclusive: true, parent: 0 }

	// Header order: pseudo-headers come first (peet preserves order). Build:
	//   pseudoHeaderOrder = first run of ':*' headers
	//   defaultHeaders   = remaining headers, in order, as { lowerKey: value }
	const pseudoHeaderOrder = []
	const defaultHeaders = {}
	let userAgent = null
	if (headersFrame && Array.isArray(headersFrame.headers)) {
		let pseudoPhase = true
		for (const h of headersFrame.headers) {
			const idx = h.indexOf(':')
			if (idx === 0) {
				// pseudo-header (starts with ':')
				const idx2 = h.indexOf(':', 1)
				const name = ':' + h.slice(1, idx2)
				if (pseudoPhase) pseudoHeaderOrder.push(name)
			} else {
				pseudoPhase = false
				const name = h.slice(0, idx).trim()
				const value = h.slice(idx + 1).trim()
				defaultHeaders[name.toLowerCase()] = value
				if (name.toLowerCase() === 'user-agent') userAgent = value
			}
		}
	}
	if (!userAgent && json.user_agent) userAgent = json.user_agent

	return {
		name: opts.name || `peet:${json.tls.ja4 || 'unnamed'}`,
		source: 'peet',
		// Reference hashes for self-verification — see the integration test:
		expected: {
			ja3:               json.tls.ja3_hash,
			ja4:               json.tls.ja4,
			akamai_fingerprint: json.http2.akamai_fingerprint_hash,
			peetprint:         json.tls.peetprint_hash,
		},

		tls: {
			ciphers: cipherCodes,
			extensionPermutation: 'shuffle-middle',
			extensionOrder,
			alpn,
			signatureAlgorithms,
			supportedGroups,
			supportedVersions,
			pskKemModes,
			keyShareGroups,
			alpsExtensionType,
			alpsProtocols,
			certCompressionAlgorithms,
			paddingLength,
		},

		http2: {
			settings,
			windowUpdateIncrement,
			sendPriorityFrame,
			priority,
			pseudoHeaderOrder: pseudoHeaderOrder.length ? pseudoHeaderOrder : [':method', ':authority', ':scheme', ':path'],
		},

		headers: Object.freeze(defaultHeaders),
		userAgent: userAgent || 'Mozilla/5.0',
	}
}

module.exports = { fromPeet }
