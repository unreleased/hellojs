// QUIC v1 packet build/parse (RFC 9000 §17).
//
// Long-header packets (Initial, Handshake, 0-RTT, Retry):
//   first byte: 1ttPPpp (1=long, t=type, P=reserved, p=pnLen-1; reserved/pnLen are
//                       under header protection so this byte is masked on the wire)
//   version: u32
//   dst_cid_len: u8, dst_cid: opaque
//   src_cid_len: u8, src_cid: opaque
//   <type-specific fields>
//   payload (encrypted)
//
// Short-header (1-RTT) packets:
//   first byte: 010KPpp1 (K=key phase under HP; spin bit; reserved; pnLen-1)
//   dst_cid: opaque (length is implicit — we only initiate so we choose our own src_cid len)
//   packet_number: 1..4 bytes
//   payload (encrypted)

const varint = require('./varint')
const keys = require('./keys')

const VERSION_V1 = 0x00000001

const PACKET_TYPE = {
	INITIAL:   0x00,
	ZERO_RTT:  0x01,
	HANDSHAKE: 0x02,
	RETRY:     0x03,
}

const FRAME_TYPE = {
	PADDING:       0x00,
	PING:          0x01,
	ACK:           0x02,
	ACK_ECN:       0x03,
	CRYPTO:        0x06,
	NEW_TOKEN:     0x07,
	STREAM_BASE:   0x08,  // 0x08..0x0f
	MAX_DATA:      0x10,
	MAX_STREAM_DATA: 0x11,
	MAX_STREAMS_BIDI: 0x12,
	MAX_STREAMS_UNI:  0x13,
	CONNECTION_CLOSE: 0x1c,
	CONNECTION_CLOSE_APP: 0x1d,
	HANDSHAKE_DONE: 0x1e,
	DATAGRAM:      0x30,  // RFC 9221 — runs to end of packet
	DATAGRAM_LEN:  0x31,  // RFC 9221 — explicit length-prefixed
	NEW_CONNECTION_ID:    0x18,
	RETIRE_CONNECTION_ID: 0x19,
	PATH_CHALLENGE:       0x1a,
	PATH_RESPONSE:        0x1b,
}

// --- Builders ---------------------------------------------------------------

// Build an Initial packet. Initial epoch always uses AES-128-GCM.
function buildInitial({ dstCid, srcCid, token = Buffer.alloc(0), payloadFrames, pn, pnLen, clientKeys }) {
	const aead = 'aes-128-gcm'
	const reservedAndPnLen = (pnLen - 1) & 0x03  // bottom 2 bits = pnLen - 1
	const firstByte = 0xc0 | (PACKET_TYPE.INITIAL << 4) | reservedAndPnLen
	const version = Buffer.alloc(4); version.writeUInt32BE(VERSION_V1, 0)
	const dstLen = Buffer.from([dstCid.length])
	const srcLen = Buffer.from([srcCid.length])
	const tokenLen = varint.encode(token.length)
	// Compute the length field: pnLen + payload length + 16 (auth tag)
	const totalProtectedLen = pnLen + payloadFrames.length + 16
	const lengthVarint = varint.encode(totalProtectedLen)
	const pnBytes = varint.encodeUint(pn, pnLen)

	const header = Buffer.concat([
		Buffer.from([firstByte]),
		version,
		dstLen, dstCid,
		srcLen, srcCid,
		tokenLen, token,
		lengthVarint,
		pnBytes,
	])
	const ciphertext = keys.aeadEncrypt(aead, clientKeys.key, clientKeys.iv, pn, header, payloadFrames)
	const packet = Buffer.concat([header, ciphertext])
	const pnOffset = header.length - pnLen
	keys.applyHeaderProtection(packet, clientKeys.hp, pnOffset, pnLen, true, aead)
	return packet
}

function buildHandshake({ dstCid, srcCid, payloadFrames, pn, pnLen, clientKeys, aead = 'aes-128-gcm' }) {
	const reservedAndPnLen = (pnLen - 1) & 0x03
	const firstByte = 0xc0 | (PACKET_TYPE.HANDSHAKE << 4) | reservedAndPnLen
	const version = Buffer.alloc(4); version.writeUInt32BE(VERSION_V1, 0)
	const dstLen = Buffer.from([dstCid.length])
	const srcLen = Buffer.from([srcCid.length])
	const totalProtectedLen = pnLen + payloadFrames.length + 16
	const lengthVarint = varint.encode(totalProtectedLen)
	const pnBytes = varint.encodeUint(pn, pnLen)
	const header = Buffer.concat([
		Buffer.from([firstByte]),
		version,
		dstLen, dstCid,
		srcLen, srcCid,
		lengthVarint,
		pnBytes,
	])
	const ciphertext = keys.aeadEncrypt(aead, clientKeys.key, clientKeys.iv, pn, header, payloadFrames)
	const packet = Buffer.concat([header, ciphertext])
	const pnOffset = header.length - pnLen
	keys.applyHeaderProtection(packet, clientKeys.hp, pnOffset, pnLen, true, aead)
	return packet
}

function buildOneRtt({ dstCid, payloadFrames, pn, pnLen, clientKeys, aead = 'aes-128-gcm', keyPhase = 0 }) {
	const reservedAndPnLen = (pnLen - 1) & 0x03
	// Short header layout: 0|1|S|R|R|K|P|P  → fixed bit (0x40), spin, reserved, K (0x04), pnLen-1.
	const firstByte = 0x40 | ((keyPhase & 0x01) << 2) | reservedAndPnLen
	const pnBytes = varint.encodeUint(pn, pnLen)
	const header = Buffer.concat([Buffer.from([firstByte]), dstCid, pnBytes])
	const ciphertext = keys.aeadEncrypt(aead, clientKeys.key, clientKeys.iv, pn, header, payloadFrames)
	const packet = Buffer.concat([header, ciphertext])
	const pnOffset = header.length - pnLen
	keys.applyHeaderProtection(packet, clientKeys.hp, pnOffset, pnLen, false, aead)
	return packet
}

// --- Parser ----------------------------------------------------------------

// Parse a single packet from the buffer. Returns { kind, ...parsedFields, consumed }.
// For Initial / Handshake we need access to keys to decrypt; for 1-RTT same.
// `keysByEpoch` is { initial: {server:{key,iv,hp}}, handshake: ..., oneRtt: ... }.
function parsePacket(buf, offset, keysByEpoch, ourSrcCidLen) {
	if (offset >= buf.length) return null
	const first = buf[offset]
	const isLong = (first & 0x80) !== 0

	if (isLong) {
		const type = (first >> 4) & 0x03
		const version = buf.readUInt32BE(offset + 1)
		let p = offset + 5
		const dstLen = buf[p++]
		const dstCid = buf.subarray(p, p + dstLen); p += dstLen
		const srcLen = buf[p++]
		const srcCid = buf.subarray(p, p + srcLen); p += srcLen

		if (type === PACKET_TYPE.RETRY) {
			// Retry has no length / pn — rest is integrity tag + token
			const tail = buf.subarray(p)
			return { kind: 'retry', version, dstCid, srcCid, retryToken: tail.subarray(0, tail.length - 16), integrityTag: tail.subarray(tail.length - 16), consumed: buf.length - offset }
		}

		let token = Buffer.alloc(0)
		if (type === PACKET_TYPE.INITIAL) {
			const tk = varint.decode(buf, p); p += tk.length
			token = buf.subarray(p, p + tk.value); p += tk.value
		}
		const lenInfo = varint.decode(buf, p); p += lenInfo.length
		const remaining = lenInfo.value
		const pnOffset = p
		const packetEndOffset = pnOffset + remaining
		// Need a copy to mutate during HP removal
		const pktSlice = Buffer.from(buf.subarray(offset, packetEndOffset))
		const localPnOffset = pnOffset - offset

		const epoch = type === PACKET_TYPE.INITIAL ? 'initial' : (type === PACKET_TYPE.HANDSHAKE ? 'handshake' : null)
		if (!epoch || !keysByEpoch[epoch]?.server) {
			return { kind: 'unknown-long', type, version, consumed: packetEndOffset - offset, dstCid, srcCid }
		}
		const sk = keysByEpoch[epoch].server
		const aead = keysByEpoch[epoch].aead || 'aes-128-gcm'
		const { firstByte: unprotected, pnLen, pn } = keys.removeHeaderProtection(pktSlice, sk.hp, localPnOffset, true, aead)
		const headerBytes = pktSlice.subarray(0, localPnOffset + pnLen)
		const ciphertext = pktSlice.subarray(localPnOffset + pnLen)
		try {
			const plaintext = keys.aeadDecrypt(aead, sk.key, sk.iv, pn, headerBytes, ciphertext)
			return { kind: epoch === 'initial' ? 'initial' : 'handshake', firstByte: unprotected, version, dstCid, srcCid, pn, payload: plaintext, consumed: packetEndOffset - offset }
		} catch (e) {
			return { kind: 'decrypt-failed', epoch, error: e.message, consumed: packetEndOffset - offset }
		}
	}

	// Short header (1-RTT). HP is unchanged across key updates so we can always remove HP
	// with the current keys; then the K bit (0x04) of the unprotected first byte selects
	// which AEAD-key set to decrypt with.
	const ek = keysByEpoch.oneRtt
	if (!ek?.server) return { kind: 'unknown-short', consumed: buf.length - offset }
	const pktSlice = Buffer.from(buf.subarray(offset))
	const localPnOffset = 1 + ourSrcCidLen
	const aead1 = ek.aead || 'aes-128-gcm'
	const { firstByte: unprotected, pnLen, pn } = keys.removeHeaderProtection(pktSlice, ek.server.hp, localPnOffset, false, aead1)
	const headerBytes = pktSlice.subarray(0, localPnOffset + pnLen)
	const ciphertext = pktSlice.subarray(localPnOffset + pnLen)
	const peerPhase = (unprotected & 0x04) >> 2
	const usingNextKeys = ek.currentPhase != null && peerPhase !== ek.currentPhase
	const aeadKeys = usingNextKeys && ek.serverNext ? ek.serverNext : ek.server
	try {
		const plaintext = keys.aeadDecrypt(aead1, aeadKeys.key, aeadKeys.iv, pn, headerBytes, ciphertext)
		return { kind: '1rtt', firstByte: unprotected, pn, payload: plaintext, peerPhase, usedNextKeys: usingNextKeys, consumed: buf.length - offset }
	} catch (e) {
		return { kind: 'decrypt-failed', epoch: '1rtt', error: e.message, peerPhase, consumed: buf.length - offset }
	}
}

// --- Frame codec ------------------------------------------------------------

// Encode a CRYPTO frame: type=0x06, offset, length, data.
function encodeCryptoFrame(offset, data) {
	return Buffer.concat([
		Buffer.from([FRAME_TYPE.CRYPTO]),
		varint.encode(offset),
		varint.encode(data.length),
		data,
	])
}

// Encode a STREAM frame with type byte 0x08..0x0f. We always set OFF (0x04) and LEN (0x02) bits, optionally FIN (0x01).
function encodeStreamFrame(streamId, offset, data, fin = false) {
	let typeByte = FRAME_TYPE.STREAM_BASE | 0x04 | 0x02 | (fin ? 0x01 : 0x00)
	return Buffer.concat([
		Buffer.from([typeByte]),
		varint.encode(streamId),
		varint.encode(offset),
		varint.encode(data.length),
		data,
	])
}

// Encode an ACK frame. `largestAcked` and `firstAckRange` are integers; we send a single contiguous range starting from largestAcked-firstAckRange to largestAcked.
function encodeAckFrame(largestAcked, ackDelay = 0, firstAckRange = 0) {
	return Buffer.concat([
		Buffer.from([FRAME_TYPE.ACK]),
		varint.encode(largestAcked),
		varint.encode(ackDelay),
		varint.encode(0),                   // ack range count
		varint.encode(firstAckRange),
	])
}

// Decode all frames from a packet payload.
function decodeFrames(buf) {
	const frames = []
	let off = 0
	while (off < buf.length) {
		const t = buf[off]
		if (t === FRAME_TYPE.PADDING) { off++; continue }
		if (t === FRAME_TYPE.PING) { frames.push({ type: 'ping' }); off++; continue }
		if (t === FRAME_TYPE.ACK || t === FRAME_TYPE.ACK_ECN) {
			off++
			const la = varint.decode(buf, off); off += la.length
			const ad = varint.decode(buf, off); off += ad.length
			const rc = varint.decode(buf, off); off += rc.length
			const fr = varint.decode(buf, off); off += fr.length
			const ranges = []
			for (let i = 0; i < rc.value; i++) {
				const gap = varint.decode(buf, off); off += gap.length
				const len = varint.decode(buf, off); off += len.length
				ranges.push({ gap: gap.value, length: len.value })
			}
			if (t === FRAME_TYPE.ACK_ECN) {
				const ect0 = varint.decode(buf, off); off += ect0.length
				const ect1 = varint.decode(buf, off); off += ect1.length
				const ce = varint.decode(buf, off); off += ce.length
			}
			frames.push({ type: 'ack', largestAcked: la.value, ackDelay: ad.value, firstAckRange: fr.value, ranges })
			continue
		}
		if (t === FRAME_TYPE.CRYPTO) {
			off++
			const offV = varint.decode(buf, off); off += offV.length
			const lenV = varint.decode(buf, off); off += lenV.length
			const data = buf.subarray(off, off + lenV.value); off += lenV.value
			frames.push({ type: 'crypto', offset: offV.value, data })
			continue
		}
		if (t >= 0x08 && t <= 0x0f) {
			const fin  = (t & 0x01) !== 0
			const hasLen  = (t & 0x02) !== 0
			const hasOff  = (t & 0x04) !== 0
			off++
			const sid = varint.decode(buf, off); off += sid.length
			let so = 0
			if (hasOff) { const v = varint.decode(buf, off); so = v.value; off += v.length }
			let dlen
			if (hasLen) { const v = varint.decode(buf, off); dlen = v.value; off += v.length }
			else { dlen = buf.length - off }
			const data = buf.subarray(off, off + dlen); off += dlen
			frames.push({ type: 'stream', streamId: sid.value, offset: so, data, fin })
			continue
		}
		if (t === FRAME_TYPE.NEW_TOKEN) {
			off++
			const lv = varint.decode(buf, off); off += lv.length
			off += lv.value
			frames.push({ type: 'new_token' })
			continue
		}
		if (t === FRAME_TYPE.HANDSHAKE_DONE) { off++; frames.push({ type: 'handshake_done' }); continue }
		if (t === FRAME_TYPE.MAX_DATA || t === FRAME_TYPE.MAX_STREAMS_BIDI || t === FRAME_TYPE.MAX_STREAMS_UNI) {
			off++
			const v = varint.decode(buf, off); off += v.length
			frames.push({ type: 'flow_control', subtype: t, value: v.value })
			continue
		}
		if (t === FRAME_TYPE.MAX_STREAM_DATA) {
			off++
			const sid = varint.decode(buf, off); off += sid.length
			const v = varint.decode(buf, off); off += v.length
			frames.push({ type: 'max_stream_data', streamId: sid.value, value: v.value })
			continue
		}
		if (t === FRAME_TYPE.PATH_CHALLENGE || t === FRAME_TYPE.PATH_RESPONSE) {
			off++
			const data = buf.subarray(off, off + 8); off += 8
			frames.push({ type: t === FRAME_TYPE.PATH_CHALLENGE ? 'path_challenge' : 'path_response', data: Buffer.from(data) })
			continue
		}
		if (t === FRAME_TYPE.NEW_CONNECTION_ID) {
			off++
			const seq = varint.decode(buf, off); off += seq.length
			const retire = varint.decode(buf, off); off += retire.length
			const clen = buf[off++]
			const cid = buf.subarray(off, off + clen); off += clen
			const token = buf.subarray(off, off + 16); off += 16
			frames.push({ type: 'new_connection_id', seq: seq.value, retirePriorTo: retire.value, cid: Buffer.from(cid), statelessResetToken: Buffer.from(token) })
			continue
		}
		if (t === FRAME_TYPE.RETIRE_CONNECTION_ID) {
			off++
			const seq = varint.decode(buf, off); off += seq.length
			frames.push({ type: 'retire_connection_id', seq: seq.value })
			continue
		}
		if (t === FRAME_TYPE.DATAGRAM || t === FRAME_TYPE.DATAGRAM_LEN) {
			off++
			let dlen
			if (t === FRAME_TYPE.DATAGRAM_LEN) {
				const v = varint.decode(buf, off); off += v.length; dlen = v.value
			} else {
				dlen = buf.length - off   // runs to end of packet
			}
			const data = buf.subarray(off, off + dlen); off += dlen
			frames.push({ type: 'datagram', data })
			continue
		}
		if (t === FRAME_TYPE.CONNECTION_CLOSE || t === FRAME_TYPE.CONNECTION_CLOSE_APP) {
			off++
			const ec = varint.decode(buf, off); off += ec.length
			if (t === FRAME_TYPE.CONNECTION_CLOSE) {
				const ft = varint.decode(buf, off); off += ft.length
			}
			const rl = varint.decode(buf, off); off += rl.length
			const reason = buf.subarray(off, off + rl.value); off += rl.value
			frames.push({ type: 'connection_close', errorCode: ec.value, reason: reason.toString('utf8') })
			continue
		}
		// Unknown frame type — log and skip to end (defensive)
		frames.push({ type: 'unknown', frameType: t, raw: buf.subarray(off) })
		break
	}
	return frames
}

// Encode a DATAGRAM frame (RFC 9221). Uses 0x31 (length-prefixed) so it can be safely
// followed by other frames in the same packet.
// RETIRE_CONNECTION_ID (RFC 9000 §19.16) — tells the peer to stop using a previously-issued CID.
function encodeRetireConnectionIdFrame(seq) {
	return Buffer.concat([Buffer.from([0x19]), varint.encode(seq)])
}

// PATH_CHALLENGE / PATH_RESPONSE (RFC 9000 §19.17, §19.18) — both carry exactly 8 bytes.
function encodePathChallengeFrame(data) {
	if (data.length !== 8) throw new Error('PATH_CHALLENGE data must be 8 bytes')
	return Buffer.concat([Buffer.from([0x1a]), data])
}

function encodePathResponseFrame(data) {
	if (data.length !== 8) throw new Error('PATH_RESPONSE data must be 8 bytes')
	return Buffer.concat([Buffer.from([0x1b]), data])
}

function encodeDatagramFrame(data) {
	const len = varint.encode(data.length)
	return Buffer.concat([Buffer.from([0x31]), len, data])
}

module.exports = {
	VERSION_V1,
	PACKET_TYPE,
	FRAME_TYPE,
	buildInitial,
	buildHandshake,
	encodeDatagramFrame,
	encodeRetireConnectionIdFrame,
	encodePathChallengeFrame,
	encodePathResponseFrame,
	buildOneRtt,
	parsePacket,
	encodeCryptoFrame,
	encodeStreamFrame,
	encodeAckFrame,
	decodeFrames,
}
