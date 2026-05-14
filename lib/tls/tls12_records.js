// TLS 1.2 record layer.
//
// Record framing is the same 5-byte TLSCiphertext header as 1.3 (type, version=0x0303,
// length). The cipher payload differs by suite:
//
//   AES-GCM (RFC 5288):
//     payload = explicit_nonce(8) || ciphertext || tag(16)
//     nonce   = implicit_iv(4) || explicit_nonce(8)
//     AAD     = seq(8) || type(1) || version(2) || plaintext_len(2)
//
//   ChaCha20-Poly1305 (RFC 7905):
//     payload = ciphertext || tag(16)         — NO explicit nonce on the wire
//     nonce   = implicit_iv(12) XOR (zero(4) || seq_be64)
//     AAD     = seq(8) || type(1) || version(2) || plaintext_len(2)
//
//   AES-CBC (RFC 5246, MAC-then-encrypt) — implemented in Phase 7+ for full Chrome
//     suite coverage. Stubbed below.

const crypto = require('crypto')

function recordHeader(type, length) {
	const h = Buffer.alloc(5)
	h[0] = type
	h[1] = 0x03; h[2] = 0x03
	h.writeUInt16BE(length, 3)
	return h
}

function seqBuf(seq) {
	const b = Buffer.alloc(8)
	b.writeUInt32BE(Math.floor(seq / 0x100000000), 0)
	b.writeUInt32BE(seq >>> 0, 4)
	return b
}

function aeadAAD(seq, type, plaintextLen) {
	const aad = Buffer.alloc(13)
	seqBuf(seq).copy(aad, 0)
	aad[8] = type
	aad[9] = 0x03; aad[10] = 0x03
	aad.writeUInt16BE(plaintextLen, 11)
	return aad
}

// Build a TLS 1.2 ciphertext record encrypting `plaintext` under AES-GCM.
function encryptGcm(aead, key, implicitIv, seq, contentType, plaintext) {
	// explicit_nonce: 8 bytes. Easiest invariant: use the sequence number (big-endian)
	// so it's unique per record under this key. Matches what mbedtls/openssl do.
	const explicitNonce = seqBuf(seq)
	const nonce = Buffer.concat([implicitIv, explicitNonce])   // 4 + 8 = 12 bytes
	const aad = aeadAAD(seq, contentType, plaintext.length)
	const c = crypto.createCipheriv(aead, key, nonce, { authTagLength: 16 })
	c.setAAD(aad)
	const ct = Buffer.concat([c.update(plaintext), c.final()])
	const tag = c.getAuthTag()
	const fragment = Buffer.concat([explicitNonce, ct, tag])
	return Buffer.concat([recordHeader(contentType, fragment.length), fragment])
}

function decryptGcm(aead, key, implicitIv, seq, contentType, ciphertextRecordPayload) {
	if (ciphertextRecordPayload.length < 8 + 16) throw new Error('TLS 1.2 GCM record too short')
	const explicitNonce = ciphertextRecordPayload.subarray(0, 8)
	const nonce = Buffer.concat([implicitIv, explicitNonce])
	const tag = ciphertextRecordPayload.subarray(ciphertextRecordPayload.length - 16)
	const ct = ciphertextRecordPayload.subarray(8, ciphertextRecordPayload.length - 16)
	const aad = aeadAAD(seq, contentType, ct.length)
	const d = crypto.createDecipheriv(aead, key, nonce, { authTagLength: 16 })
	d.setAAD(aad)
	d.setAuthTag(tag)
	return Buffer.concat([d.update(ct), d.final()])
}

// ChaCha20-Poly1305: no explicit nonce. Nonce = iv XOR (zero(4) || seq_be64).
function encryptChaCha(key, implicitIv12, seq, contentType, plaintext) {
	const nonce = Buffer.from(implicitIv12)
	const sBuf = seqBuf(seq)
	for (let i = 0; i < 8; i++) nonce[4 + i] ^= sBuf[i]
	const aad = aeadAAD(seq, contentType, plaintext.length)
	const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
	c.setAAD(aad)
	const ct = Buffer.concat([c.update(plaintext), c.final()])
	const tag = c.getAuthTag()
	const fragment = Buffer.concat([ct, tag])
	return Buffer.concat([recordHeader(contentType, fragment.length), fragment])
}

function decryptChaCha(key, implicitIv12, seq, contentType, ciphertextRecordPayload) {
	if (ciphertextRecordPayload.length < 16) throw new Error('TLS 1.2 ChaCha20 record too short')
	const nonce = Buffer.from(implicitIv12)
	const sBuf = seqBuf(seq)
	for (let i = 0; i < 8; i++) nonce[4 + i] ^= sBuf[i]
	const tag = ciphertextRecordPayload.subarray(ciphertextRecordPayload.length - 16)
	const ct = ciphertextRecordPayload.subarray(0, ciphertextRecordPayload.length - 16)
	const aad = aeadAAD(seq, contentType, ct.length)
	const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
	d.setAAD(aad)
	d.setAuthTag(tag)
	return Buffer.concat([d.update(ct), d.final()])
}

// CBC (RFC 5246 §6.2.3.2) — MAC-then-encrypt.
//   wire payload = IV(16) || enc_CBC(content || MAC || padding[padLen] || padLen)
//   MAC = HMAC(macKey, seq(8) || type(1) || version(2) || content_length(2) || content)
//   padding: padLen bytes all equal to padLen, then 1 byte = padLen. Total encrypted
//   region is a multiple of blocksize.
function encryptCbc(cipher, encKey, macKey, seq, contentType, plaintext) {
	const macAlg = cipher.mac
	const macLen = cipher.macLen
	const blockSize = 16

	// MAC over seq + type + version + plaintext_length + plaintext
	const macInput = Buffer.alloc(13 + plaintext.length)
	seqBuf(seq).copy(macInput, 0)
	macInput[8] = contentType
	macInput[9] = 0x03; macInput[10] = 0x03
	macInput.writeUInt16BE(plaintext.length, 11)
	plaintext.copy(macInput, 13)
	const mac = crypto.createHmac(macAlg, macKey).update(macInput).digest()

	// padding: padLen padding bytes + 1 padLen byte. Total = plaintext + MAC + padding + 1
	// must be multiple of blockSize.
	const lenSoFar = plaintext.length + macLen
	const padLen = blockSize - 1 - (lenSoFar % blockSize)
	const padding = Buffer.alloc(padLen + 1, padLen)

	const toEncrypt = Buffer.concat([plaintext, mac, padding])

	const iv = crypto.randomBytes(blockSize)
	const aesAlg = encKey.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc'
	const c = crypto.createCipheriv(aesAlg, encKey, iv)
	c.setAutoPadding(false)
	const enc = Buffer.concat([c.update(toEncrypt), c.final()])

	const fragment = Buffer.concat([iv, enc])
	return Buffer.concat([recordHeader(contentType, fragment.length), fragment])
}

function decryptCbc(cipher, encKey, macKey, seq, contentType, payload) {
	const blockSize = 16
	const aesAlg = encKey.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc'
	const iv = payload.subarray(0, blockSize)
	const ct = payload.subarray(blockSize)
	const d = crypto.createDecipheriv(aesAlg, encKey, iv)
	d.setAutoPadding(false)
	const pt = Buffer.concat([d.update(ct), d.final()])

	// Strip padding
	const padLen = pt[pt.length - 1]
	if (padLen + 1 > pt.length) throw new Error('CBC: invalid padding')
	for (let i = pt.length - 1 - padLen; i < pt.length; i++) {
		if (pt[i] !== padLen) throw new Error('CBC: bad padding byte')
	}
	const noPad = pt.subarray(0, pt.length - padLen - 1)

	// Strip MAC and verify
	const macLen = cipher.macLen
	const content = noPad.subarray(0, noPad.length - macLen)
	const mac = noPad.subarray(noPad.length - macLen)

	const macInput = Buffer.alloc(13 + content.length)
	seqBuf(seq).copy(macInput, 0)
	macInput[8] = contentType
	macInput[9] = 0x03; macInput[10] = 0x03
	macInput.writeUInt16BE(content.length, 11)
	content.copy(macInput, 13)
	const expected = crypto.createHmac(cipher.mac, macKey).update(macInput).digest()
	if (!crypto.timingSafeEqual(mac, expected)) throw new Error('CBC: MAC mismatch')
	return content
}

// Dispatcher: pick the right encrypt/decrypt based on cipher.aead.
function encryptRecord(cipher, keys, seq, contentType, plaintext) {
	if (cipher.aead === 'aes-128-gcm' || cipher.aead === 'aes-256-gcm') {
		return encryptGcm(cipher.aead, keys.key, keys.iv, seq, contentType, plaintext)
	}
	if (cipher.aead === 'chacha20-poly1305') {
		return encryptChaCha(keys.key, keys.iv, seq, contentType, plaintext)
	}
	if (cipher.mac) {   // CBC
		return encryptCbc(cipher, keys.key, keys.mac, seq, contentType, plaintext)
	}
	throw new Error(`encryptRecord: unsupported cipher ${cipher.name}`)
}

function decryptRecord(cipher, keys, seq, contentType, payload) {
	if (cipher.aead === 'aes-128-gcm' || cipher.aead === 'aes-256-gcm') {
		return decryptGcm(cipher.aead, keys.key, keys.iv, seq, contentType, payload)
	}
	if (cipher.aead === 'chacha20-poly1305') {
		return decryptChaCha(keys.key, keys.iv, seq, contentType, payload)
	}
	if (cipher.mac) {
		return decryptCbc(cipher, keys.key, keys.mac, seq, contentType, payload)
	}
	throw new Error(`decryptRecord: unsupported cipher ${cipher.name}`)
}

module.exports = {
	recordHeader, aeadAAD, seqBuf,
	encryptGcm, decryptGcm,
	encryptChaCha, decryptChaCha,
	encryptRecord, decryptRecord,
}
