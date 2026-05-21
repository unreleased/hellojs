// profiles.fromPeet — paste a peet.ws response, get a profile that emits the same fingerprint.

const test = require('node:test')
const assert = require('node:assert')
const { fromPeet } = require('../../lib/profiles/from-peet')

const SAMPLE = {
	user_agent: 'Mozilla/5.0 ... Chrome/147.0.0.0 Safari/537.36',
	tls: {
		ciphers: [
			'TLS_GREASE (0x4A4A)',
			'TLS_AES_128_GCM_SHA256',
			'TLS_AES_256_GCM_SHA384',
			'TLS_CHACHA20_POLY1305_SHA256',
			'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
			'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
			'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
			'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
			'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
			'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
			'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
			'TLS_RSA_WITH_AES_128_GCM_SHA256',
			'TLS_RSA_WITH_AES_256_GCM_SHA384',
			'TLS_RSA_WITH_AES_128_CBC_SHA',
			'TLS_RSA_WITH_AES_256_CBC_SHA',
		],
		extensions: [
			{ name: 'TLS_GREASE (0x6a6a)' },
			{ name: 'session_ticket (35)', data: '' },
			{ name: 'extensionEncryptedClientHello (boringssl) (65037)', data: '...' },
			{ name: 'supported_groups (10)', supported_groups: ['TLS_GREASE (0x7a7a)', 'X25519MLKEM768 (4588)', 'X25519 (29)', 'P-256 (23)', 'P-384 (24)'] },
			{ name: 'application_layer_protocol_negotiation (16)', protocols: ['h2', 'http/1.1'] },
			{ name: 'supported_versions (43)', versions: ['TLS_GREASE (0x8a8a)', 'TLS 1.3', 'TLS 1.2'] },
			{ name: 'signature_algorithms (13)', signature_algorithms: [
				'ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256',
				'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384',
				'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512',
			] },
			{ name: 'psk_key_exchange_modes (45)', PSK_Key_Exchange_Mode: 'PSK with (EC)DHE key establishment (psk_dhe_ke) (1)' },
			{ name: 'extended_master_secret (23)' },
			{ name: 'key_share (51)', shared_keys: [
				{ 'TLS_GREASE (0x7a7a)': '00' },
				{ 'X25519MLKEM768 (4588)': 'aabb' },
				{ 'X25519 (29)': 'aabb' },
			] },
			{ name: 'application_settings (17613)', protocols: ['h2'] },
			{ name: 'extensionRenegotiationInfo (boringssl) (65281)', data: '00' },
			{ name: 'ec_point_formats (11)', elliptic_curves_point_formats: ['0x00'] },
			{ name: 'server_name (0)', server_name: 'tls.peet.ws' },
			{ name: 'signed_certificate_timestamp (18)' },
			{ name: 'compress_certificate (27)', algorithms: ['brotli (2)'] },
			{ name: 'status_request (5)' },
			{ name: 'TLS_GREASE (0x7a7a)' },
		],
		ja3_hash: '6ca16c714c730295e4b3eb9ed9f9109b',
		ja4: 't13d1516h2_8daaf6152771_d8a2da3f94cd',
		peetprint_hash: '1d4ffe9b0e34acac0bd883fa7f79d7b5',
	},
	http2: {
		akamai_fingerprint_hash: '52d84b11737d980aef856699f885ca86',
		sent_frames: [
			{ frame_type: 'SETTINGS', settings: [
				'HEADER_TABLE_SIZE = 65536', 'ENABLE_PUSH = 0', 'INITIAL_WINDOW_SIZE = 6291456', 'MAX_HEADER_LIST_SIZE = 262144',
			] },
			{ frame_type: 'WINDOW_UPDATE', increment: 15663105 },
			{ frame_type: 'HEADERS', stream_id: 1, flags: ['EndStream (0x1)', 'EndHeaders (0x4)', 'Priority (0x20)'],
				priority: { weight: 256, depends_on: 0, exclusive: 1 },
				headers: [
					':method: GET',
					':authority: tls.peet.ws',
					':scheme: https',
					':path: /api/all',
					'sec-ch-ua: "Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
					'sec-ch-ua-mobile: ?0',
					'user-agent: Mozilla/5.0 Chrome/147.0',
					'accept: text/html',
					'accept-encoding: gzip, deflate, br, zstd',
				],
			},
		],
	},
}

test('fromPeet: cipher list omits GREASE and preserves order', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.tls.ciphers.length, 15)
	assert.strictEqual(p.tls.ciphers[0], 0x1301)
	assert.strictEqual(p.tls.ciphers[1], 0x1302)
})

test('fromPeet: supportedGroups omits GREASE, preserves order', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.tls.supportedGroups, [0x11ec, 0x001d, 0x0017, 0x0018])
})

test('fromPeet: keyShareGroups parsed from peet shared_keys', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.tls.keyShareGroups, [0x11ec, 0x001d])
})

test('fromPeet: signatureAlgorithms in order', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.tls.signatureAlgorithms, [
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
	])
})

test('fromPeet: ALPN order', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.tls.alpn, ['h2', 'http/1.1'])
})

test('fromPeet: HTTP/2 settings parsed', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.http2.settings.headerTableSize, 65536)
	assert.strictEqual(p.http2.settings.enablePush, false)
	assert.strictEqual(p.http2.settings.initialWindowSize, 6291456)
	assert.strictEqual(p.http2.settings.maxHeaderListSize, 262144)
	assert.strictEqual(p.http2.windowUpdateIncrement, 15663105)
})

test('fromPeet: PRIORITY flag + priority values parsed', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.http2.sendPriorityFrame, true)
	assert.deepStrictEqual(p.http2.priority, { weight: 256, parent: 0, exclusive: true })
})

test('fromPeet: pseudo-header order from HEADERS frame', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.http2.pseudoHeaderOrder, [':method', ':authority', ':scheme', ':path'])
})

test('fromPeet: default headers + user-agent parsed', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.headers['sec-ch-ua-mobile'], '?0')
	assert.strictEqual(p.headers['accept-encoding'], 'gzip, deflate, br, zstd')
	assert.match(p.userAgent, /Chrome\/147/)
})

test('fromPeet: ALPS extension type detected (44CD = v1)', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.tls.alpsExtensionType, 17613)
	assert.deepStrictEqual(p.tls.alpsProtocols, ['h2'])
})

test('fromPeet: cert compression algorithms parsed', () => {
	const p = fromPeet(SAMPLE)
	assert.deepStrictEqual(p.tls.certCompressionAlgorithms, [2])
})

test('fromPeet: expected hashes captured for self-verification', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.expected.ja4, 't13d1516h2_8daaf6152771_d8a2da3f94cd')
	assert.strictEqual(p.expected.akamai_fingerprint, '52d84b11737d980aef856699f885ca86')
})

test('fromPeet: rejects non-peet inputs', () => {
	assert.throws(() => fromPeet({}), /does not look like a peet\.ws response/)
	assert.throws(() => fromPeet(null), /does not look like a peet\.ws response/)
})

test('registerFromPeet: registers + returns profile', () => {
	const profiles = require('../../lib/profiles')
	const p = profiles.registerFromPeet('parrot-test', SAMPLE)
	assert.strictEqual(p.name, 'parrot-test')
	assert.strictEqual(profiles.get('parrot-test'), p)
})

test('fromPeet: detects useGrease=true when GREASE appears anywhere', () => {
	const p = fromPeet(SAMPLE)
	assert.strictEqual(p.tls.useGrease, true)
})

// Regression: this parrot is a real capture of a non-Chrome client (TLS 1.2 only, no GREASE,
// status_request_v2, signature_algorithms_cert, bare-hex sigalgs). Every assertion in this
// test corresponds to a Phase-1 fix:
//   - TLS_EMPTY_RENEGOTIATION_INFO alias (CIPHERS missing 0x00ff)
//   - rsa_pss_pss_sha{256,384,512} + ecdsa_sha1 added to SIGALG_BY_NAME
//   - bare "0x402" / "0x303" / "0x301" / "0x302" / "0x202" parse via extractBare
//   - useGrease=false because input has zero GREASE markers
//   - extension 50 raw bytes captured for byte-exact emission
//   - status_request_v2 shape captured
const fs = require('node:fs')
const path = require('node:path')
const MIDDLEBOX = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/middlebox-tls12-peet.json'), 'utf8'))

test('fromPeet (middlebox-tls12): parses without throwing', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.ok(p)
})

test('fromPeet (middlebox-tls12): cipher list includes SCSV (0x00ff) at end', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.strictEqual(p.tls.ciphers.length, 13)
	assert.strictEqual(p.tls.ciphers[p.tls.ciphers.length - 1], 0x00ff)
})

test('fromPeet (middlebox-tls12): useGrease=false', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.strictEqual(p.tls.useGrease, false)
})

test('fromPeet (middlebox-tls12): supportedVersions = [TLS 1.2] only', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.deepStrictEqual(p.tls.supportedVersions, [0x0303])
})

test('fromPeet (middlebox-tls12): full sigalg list incl. rsa_pss_pss_* + bare-hex codepoints', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.deepStrictEqual(p.tls.signatureAlgorithms, [
		0x0403, 0x0503, 0x0603,
		0x0804, 0x0805, 0x0806,
		0x0809, 0x080a, 0x080b,
		0x0401, 0x0501, 0x0601,
		0x0402, 0x0303, 0x0301, 0x0302,
		0x0203, 0x0201, 0x0202,
	])
})

test('fromPeet (middlebox-tls12): signature_algorithms_cert raw bytes captured', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.ok(Buffer.isBuffer(p.tls.signatureAlgorithmsCertRaw))
	assert.strictEqual(p.tls.signatureAlgorithmsCertRaw.length, 40)
	// First two bytes are the inner-list length (38 = 0x0026).
	assert.strictEqual(p.tls.signatureAlgorithmsCertRaw.readUInt16BE(0), 0x0026)
	// Parsed list matches the raw body.
	assert.strictEqual(p.tls.signatureAlgorithmsCert.length, 19)
	assert.strictEqual(p.tls.signatureAlgorithmsCert[0], 0x0403)
})

test('fromPeet (middlebox-tls12): status_request_v2 shape captured', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.deepStrictEqual(p.tls.statusRequestV2, {
		certificateStatusType: 0,
		responderIdListLength: 7,
		requestExtensionsLength: 2,
	})
})

test('fromPeet (middlebox-tls12): extensionOrder preserves ids incl. 17 and 50', () => {
	const p = fromPeet(MIDDLEBOX)
	const ids = p.tls.extensionOrder.filter(e => !e.grease).map(e => e.id)
	assert.deepStrictEqual(ids, [0, 5, 10, 11, 13, 50, 16, 17, 23, 43])
})

test('fromPeet (middlebox-tls12): supportedGroups (no MLKEM, no GREASE)', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.deepStrictEqual(p.tls.supportedGroups, [0x001d, 0x0017, 0x0018, 0x0019, 0x001e])
})

test('fromPeet (middlebox-tls12): H/2 settings + WINDOW_UPDATE captured', () => {
	const p = fromPeet(MIDDLEBOX)
	assert.strictEqual(p.http2.settings.enablePush, false)
	assert.strictEqual(p.http2.settings.maxHeaderListSize, 262144)
	assert.strictEqual(p.http2.windowUpdateIncrement, 10485760)
	assert.strictEqual(p.http2.sendPriorityFrame, false)
})
