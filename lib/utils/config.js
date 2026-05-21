/**
 * Config variables to make code easier to read and understand
 * These values are hardcoded in TLS spec.
 */

const MESSAGE_TYPES = {
	CLIENT_HELLO: 0x01,
	SERVER_HELLO: 0x02,
	END_OF_EARLY_DATA: 0x05,
	HANDSHAKE: 0x16,
	ENCRYPTED_EXTENSIONS: 0x08,
	SERVER_CERTIFICATE: 0x0b,
	SERVER_CERTIFICATE_VERIFY: 0x0f,
	FINISHED: 0x14,
	APPLICATION_DATA: 0x17,
	ALERT: 0x15,
}


const CIPHERS = {
	GREASE: 0x1a1a,
	TLS_AES_128_GCM_SHA256: 0x1301,
	TLS_AES_256_GCM_SHA384: 0x1302,
	TLS_CHACHA20_POLY1305_SHA256: 0x1303,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xC02B,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xC02F,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xC02C,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xC030,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xCCA9,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xCCA8,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: 0xC013,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: 0xC014,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: 0xC009,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: 0xC00A,
	TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009C,
	TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009D,
	TLS_RSA_WITH_AES_128_CBC_SHA: 0x002F,
	TLS_RSA_WITH_AES_256_CBC_SHA: 0x0035,
	// Legacy 3DES — never negotiated, advertised only to match browser fingerprints (Safari).
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: 0xC008,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: 0xC012,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA: 0x000A,
	// RFC 5746 signaling SCSV — TLS-1.2 clients that don't send the renegotiation_info
	// extension include this in their cipher list instead. peet labels it without the
	// _SCSV suffix; from-peet.js accepts the alias.
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV: 0x00FF,
}

const HASHES = {
	"1301": {
		hash: "sha256",
		aead: 'aes-128-gcm',
		keyLen: 16,
		hashLen: 32,
		ivLen: 12,
	},
	"1302": {
		hash: "sha384",
		aead: 'aes-256-gcm',
		keyLen: 32,
		hashLen: 48,
		ivLen: 12,
	},
	"1303": {
		hash: "sha256",
		aead: 'chacha20-poly1305',
		keyLen: 32,
		hashLen: 32,
		ivLen: 12,
	}
}

module.exports = {
	MESSAGE_TYPES,
	CIPHERS,
	HASHES
}