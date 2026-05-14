// QUIC v1 key derivation (RFC 9001 §5.2) + packet protection helpers (§5.4).
//
// Initial keys are derived from the client's destination connection ID using a
// fixed initial_salt. Handshake / 1-RTT keys come from the TLS exporter secrets.

const crypto = require('crypto')
const HKDF = require('../utils/hkdf')

// RFC 9001 §5.2: initial_salt for QUIC v1
const INITIAL_SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex')

const HASH_LEN_SHA256 = 32

// Returns { client: {key, iv, hp, secret}, server: {key, iv, hp, secret} } for the Initial epoch.
// AEAD = AES-128-GCM, hash = SHA-256, key length 16, iv length 12, hp key length 16.
function deriveInitialKeys(dstConnectionId) {
	const initialSecret = HKDF.Extract('sha256', INITIAL_SALT_V1, dstConnectionId)
	const clientInitialSecret = HKDF.ExpandLabel(initialSecret, 'client in', Buffer.alloc(0), HASH_LEN_SHA256, 'sha256', HASH_LEN_SHA256)
	const serverInitialSecret = HKDF.ExpandLabel(initialSecret, 'server in', Buffer.alloc(0), HASH_LEN_SHA256, 'sha256', HASH_LEN_SHA256)
	return {
		client: deriveKeysFromSecret(clientInitialSecret, 'sha256', 16, 12),
		server: deriveKeysFromSecret(serverInitialSecret, 'sha256', 16, 12),
	}
}

function deriveKeysFromSecret(secret, hash, keyLen, ivLen) {
	return {
		secret,
		key: HKDF.ExpandLabel(secret, 'quic key', Buffer.alloc(0), keyLen, hash, secret.length),
		iv:  HKDF.ExpandLabel(secret, 'quic iv',  Buffer.alloc(0), ivLen, hash, secret.length),
		hp:  HKDF.ExpandLabel(secret, 'quic hp',  Buffer.alloc(0), keyLen, hash, secret.length),
	}
}

// RFC 9001 §6.1: next-phase 1-RTT traffic secret. HP key is unchanged across key updates;
// only the AEAD key + iv rotate.
function deriveKeyUpdate(currentSecret, hash, keyLen, ivLen, hpKeyFromPrev) {
	const next = HKDF.ExpandLabel(currentSecret, 'quic ku', Buffer.alloc(0), currentSecret.length, hash, currentSecret.length)
	return {
		secret: next,
		key: HKDF.ExpandLabel(next, 'quic key', Buffer.alloc(0), keyLen, hash, next.length),
		iv:  HKDF.ExpandLabel(next, 'quic iv',  Buffer.alloc(0), ivLen, hash, next.length),
		hp:  hpKeyFromPrev,   // HP key is NOT rotated on key update
	}
}

// Build the AEAD nonce for a given packet number: pad pn to iv length and XOR with iv.
function nonceForPacketNumber(iv, pn) {
	const out = Buffer.from(iv)
	const pnBuf = Buffer.alloc(8)
	pnBuf.writeBigUInt64BE(BigInt(pn), 0)
	for (let i = 0; i < 8; i++) out[out.length - 8 + i] ^= pnBuf[i]
	return out
}

// Encrypt the packet payload (everything after the packet number bytes). Returns the
// ciphertext+tag. The AAD is the unprotected packet header (everything from the first byte
// up to and including the packet number bytes).
function aeadEncrypt(aead, key, iv, pn, header, payload) {
	const nonce = nonceForPacketNumber(iv, pn)
	const cipher = crypto.createCipheriv(aead, key, nonce, { authTagLength: 16 })
	cipher.setAAD(header)
	const ct = Buffer.concat([cipher.update(payload), cipher.final()])
	return Buffer.concat([ct, cipher.getAuthTag()])
}

function aeadDecrypt(aead, key, iv, pn, header, ciphertext) {
	const nonce = nonceForPacketNumber(iv, pn)
	const tag = ciphertext.subarray(ciphertext.length - 16)
	const ct = ciphertext.subarray(0, ciphertext.length - 16)
	const dec = crypto.createDecipheriv(aead, key, nonce, { authTagLength: 16 })
	dec.setAAD(header)
	dec.setAuthTag(tag)
	return Buffer.concat([dec.update(ct), dec.final()])
}

// Header protection: RFC 9001 §5.4. AES variants: mask = AES-ECB(hp, sample). ChaCha20: per §5.4.4 use ChaCha20 stream with counter=sample[0:4] LE, nonce=sample[4:16], encrypt 5 zero bytes.
function aesHeaderProtectionMask(hpKey, sample) {
	if (sample.length !== 16) throw new Error('hp sample must be 16 bytes')
	const ecb = hpKey.length === 16 ? 'aes-128-ecb' : 'aes-256-ecb'
	const c = crypto.createCipheriv(ecb, hpKey, null)
	c.setAutoPadding(false)
	return Buffer.concat([c.update(sample), c.final()]).subarray(0, 5)
}

// ChaCha20 header-protection mask. Node's crypto exposes ChaCha20 via `chacha20-poly1305` AEAD only — for raw ChaCha20 we use the 'chacha20' cipher (stream cipher mode).
function chacha20HeaderProtectionMask(hpKey, sample) {
	if (sample.length !== 16) throw new Error('hp sample must be 16 bytes')
	if (hpKey.length !== 32) throw new Error('chacha20 hp key must be 32 bytes')
	// Construct an IV: counter (4 bytes LE from sample[0:4]) + nonce (12 bytes from sample[4:16]).
	// Node's 'chacha20' cipher takes a 16-byte IV: 4 bytes counter (LE) + 12 bytes nonce.
	const iv = Buffer.concat([sample.subarray(0, 4), sample.subarray(4, 16)])
	const c = crypto.createCipheriv('chacha20', hpKey, iv)
	const enc = c.update(Buffer.alloc(5, 0))
	c.final()
	return enc
}

function headerProtectionMask(hpKey, sample, aead) {
	if (aead === 'chacha20-poly1305') return chacha20HeaderProtectionMask(hpKey, sample)
	return aesHeaderProtectionMask(hpKey, sample)
}

function applyHeaderProtection(packet, hpKey, pnOffset, pnLen, longHeader, aead) {
	const sample = packet.subarray(pnOffset + 4, pnOffset + 4 + 16)
	const mask = headerProtectionMask(hpKey, sample, aead)
	const lowBits = longHeader ? 0x0f : 0x1f
	packet[0] ^= mask[0] & lowBits
	for (let i = 0; i < pnLen; i++) packet[pnOffset + i] ^= mask[1 + i]
}

function removeHeaderProtection(packet, hpKey, pnOffset, longHeader, aead) {
	const sample = packet.subarray(pnOffset + 4, pnOffset + 4 + 16)
	const mask = headerProtectionMask(hpKey, sample, aead)
	const lowBits = longHeader ? 0x0f : 0x1f
	packet[0] ^= mask[0] & lowBits
	const pnLen = (packet[0] & 0x03) + 1
	for (let i = 0; i < pnLen; i++) packet[pnOffset + i] ^= mask[1 + i]
	let pn = 0
	for (let i = 0; i < pnLen; i++) pn = (pn << 8) | packet[pnOffset + i]
	return { firstByte: packet[0], pnLen, pn }
}

module.exports = {
	INITIAL_SALT_V1,
	deriveInitialKeys,
	deriveKeysFromSecret,
	deriveKeyUpdate,
	nonceForPacketNumber,
	aeadEncrypt,
	aeadDecrypt,
	aesHeaderProtectionMask,
	chacha20HeaderProtectionMask,
	headerProtectionMask,
	applyHeaderProtection,
	removeHeaderProtection,
}
