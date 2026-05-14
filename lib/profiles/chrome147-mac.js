// Chrome 147 on macOS profile — pinned values that produce a fingerprint identical to
// the real browser captured in test/fixtures/chrome147-peet.json.

const { CIPHERS } = require('../utils/config')

module.exports = {
	name: 'chrome147-mac',

	tls: {
		// Cipher list (exclusive of GREASE which is added at runtime per connection)
		ciphers: [
			CIPHERS.TLS_AES_128_GCM_SHA256,
			CIPHERS.TLS_AES_256_GCM_SHA384,
			CIPHERS.TLS_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_256_CBC_SHA,
		],

		// Per-instance extension permutation. true = pinned at start/end (GREASE).
		// All other extensions are shuffled per-instance.
		extensionPermutation: 'shuffle-middle',

		// ALPN order (Chrome prefers h2)
		alpn: ['h2', 'http/1.1'],

		// signature_algorithms (RFC 8446 §4.2.3) — exact Chrome 147 list, in order
		signatureAlgorithms: [
			0x0403, // ecdsa_secp256r1_sha256
			0x0804, // rsa_pss_rsae_sha256
			0x0401, // rsa_pkcs1_sha256
			0x0503, // ecdsa_secp384r1_sha384
			0x0805, // rsa_pss_rsae_sha384
			0x0501, // rsa_pkcs1_sha384
			0x0806, // rsa_pss_rsae_sha512
			0x0601, // rsa_pkcs1_sha512
		],

		// supported_groups (excl. GREASE)
		supportedGroups: [0x11ec, 0x001d, 0x0017, 0x0018], // X25519MLKEM768, X25519, P-256, P-384

		// Which groups to send a key_share for (key_share entries are MLKEM hybrid + X25519)
		keyShareGroups: [0x11ec, 0x001d],

		// ALPS extension type (0x44CD = v1; 0x4469 = v2). Chrome 147 still uses v1.
		alpsExtensionType: 0x44cd,
		alpsProtocols: ['h2'],

		// compress_certificate algorithms — brotli only
		certCompressionAlgorithms: [0x0002], // brotli
	},

	http2: {
		// SETTINGS values + insertion order (matters for fingerprint)
		settings: {
			headerTableSize: 65536,
			enablePush: false,
			initialWindowSize: 6291456,
			maxHeaderListSize: 262144,
		},

		// Connection-level WINDOW_UPDATE increment
		windowUpdateIncrement: 15663105,

		// Whether to send a PRIORITY frame on stream 1 (Chrome 147: yes)
		sendPriorityFrame: true,
		priority: { weight: 256, exclusive: true, parent: 0 },

		// Pseudo-header order
		pseudoHeaderOrder: [':method', ':authority', ':scheme', ':path'],
	},

	headers: require('../headers').CHROME_147_DEFAULT_HEADERS,
	userAgent: require('../headers').CHROME_147_UA,
}
