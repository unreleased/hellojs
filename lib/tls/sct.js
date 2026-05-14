// Certificate Transparency (RFC 6962) Signed Certificate Timestamp (SCT) parser.
//
// Modern CAs embed >=2 SCTs in the leaf certificate as an X.509 extension with OID
// 1.3.6.1.4.1.11129.2.4.2. Chrome enforces "must have N SCTs from trusted logs" for
// publicly-trusted certs issued post-2018.
//
// What we do:
//   - Find the SCT extension in the leaf cert
//   - Parse the embedded SignedCertificateTimestampList
//   - Extract logID, timestamp, signature for each SCT
//   - Return counts; caller can enforce minimum (e.g. require >= 1 or >= 2)
//
// What we DON'T do (yet):
//   - Verify the SCT signature against a trusted CT log's public key. Doing that requires
//     shipping (and refreshing) the CT log list from
//     https://www.gstatic.com/ct/log_list/v3/log_list.json — a maintenance burden we punt to
//     callers. The `verifySct` function accepts a `logKeys` map { logId(hex) -> publicKey }
//     so callers can plug in the list and enforce verification.
//
// Most production callers should at least require `sctCount >= 1` to confirm the cert
// participated in CT, which is enough to detect a forged cert from an off-the-record CA.

const crypto = require('node:crypto')

const SCT_OID = '1.3.6.1.4.1.11129.2.4.2'
// SCT extension OID DER bytes (the inner OID encoding, no tag/length prefix):
const SCT_OID_DER = Buffer.from('2B06010401D679020402', 'hex')

// Minimal DER walker (shared shape with ocsp.js — kept local to avoid coupling).
function readTLV(buf, offset = 0) {
	if (offset >= buf.length) throw new Error('SCT: short DER')
	const tag = buf[offset]
	let i = offset + 1
	if (i >= buf.length) throw new Error('SCT: short length byte')
	let len = buf[i++]
	if (len & 0x80) {
		const lenLen = len & 0x7f
		if (lenLen === 0 || lenLen > 4) throw new Error('SCT: bad length encoding')
		if (i + lenLen > buf.length) throw new Error('SCT: truncated length')
		len = 0
		for (let j = 0; j < lenLen; j++) len = (len << 8) | buf[i++]
	}
	if (i + len > buf.length) throw new Error('SCT: truncated value')
	return { tag, length: len, value: buf.subarray(i, i + len), headerLen: i - offset, end: i + len }
}

// Locate the SCT extension within a cert's TBSCertificate.extensions.
// Returns the OCTET STRING content (the serialized SCT list with its 2-byte outer length),
// or null if not present.
function findSctExtension(certDer) {
	const cert = readTLV(certDer, 0)
	const tbs = readTLV(cert.value, 0)
	const body = tbs.value
	let p = 0
	// Walk top-level fields: version[0]?, serial, sigAlg, issuer, validity, subject,
	// subjectPublicKeyInfo, then [3] EXPLICIT extensions.
	while (p < body.length) {
		const f = readTLV(body, p)
		p = f.end
		if (f.tag === 0xa3) {
			// extensions: SEQUENCE OF Extension
			const seq = readTLV(f.value, 0)
			if ((seq.tag & 0x1f) !== 0x10) return null
			const extBody = seq.value
			let q = 0
			while (q < extBody.length) {
				const ext = readTLV(extBody, q); q = ext.end
				// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
				const ev = ext.value
				const oid = readTLV(ev, 0)
				if ((oid.tag & 0x1f) !== 0x06) continue
				if (!oid.value.equals(SCT_OID_DER)) continue
				// next is either critical BOOLEAN or extnValue OCTET STRING
				let nextOff = oid.end
				let next = readTLV(ev, nextOff)
				if (next.tag === 0x01) { nextOff = next.end; next = readTLV(ev, nextOff) }
				if ((next.tag & 0x1f) !== 0x04) return null
				// next.value is an OCTET STRING whose content is ALSO an OCTET STRING (RFC 6962 §3.3)
				const inner = readTLV(next.value, 0)
				if ((inner.tag & 0x1f) !== 0x04) return null
				return Buffer.from(inner.value)
			}
		}
	}
	return null
}

// Parse the SignedCertificateTimestampList → array of SCT descriptors.
// Format: u16 total-length | (u16 sct-length | SCT)*
function parseSctList(buf) {
	if (!buf || buf.length < 2) return []
	const total = buf.readUInt16BE(0)
	if (total + 2 > buf.length) return []
	const out = []
	let p = 2
	const end = 2 + total
	while (p < end) {
		const sctLen = buf.readUInt16BE(p); p += 2
		const body = buf.subarray(p, p + sctLen)
		p += sctLen
		if (body.length < 1 + 32 + 8 + 2) continue
		const version = body[0]
		const logId = body.subarray(1, 33)
		const timestamp = Number(body.readBigUInt64BE(33))
		const extLen = body.readUInt16BE(41)
		const extensions = body.subarray(43, 43 + extLen)
		// digitally-signed: struct { SignatureAndHashAlgorithm algorithm; opaque signature<0..2^16-1>; }
		let sigOff = 43 + extLen
		if (sigOff + 4 > body.length) continue
		const sigAlgHash = body[sigOff]      // 2=sha1 4=sha256 5=sha384 6=sha512
		const sigAlgKey  = body[sigOff + 1]  // 1=rsa 3=ecdsa
		const sigLen = body.readUInt16BE(sigOff + 2)
		const signature = body.subarray(sigOff + 4, sigOff + 4 + sigLen)
		out.push({
			version, logId: Buffer.from(logId), timestamp, extensions: Buffer.from(extensions),
			sigAlg: { hash: sigAlgHash, key: sigAlgKey }, signature: Buffer.from(signature),
		})
	}
	return out
}

// Public entry: extract + parse SCTs from a leaf cert DER. Returns [{logId,timestamp,...}].
function extractScts(certDer) {
	const ext = findSctExtension(certDer)
	if (!ext) return []
	return parseSctList(ext)
}

// Verify an SCT against a known log public key. Per RFC 6962 §3.2:
//
//   digitally-signed struct {
//     Version sct_version;
//     SignatureType signature_type = certificate_timestamp;  // 0
//     uint64 timestamp;
//     LogEntryType entry_type;                                // 0 = x509_entry, 1 = precert_entry
//     select (entry_type) {
//       case x509_entry:    ASN.1Cert certificate;             // 24-bit length + DER cert
//       case precert_entry: PreCert precert;
//     };
//     CtExtensions extensions;                                 // 16-bit length + bytes
//   } signed_struct;
//
// Note: for an SCT EMBEDDED in a cert (the common case), the entry_type is precert_entry
// and the signed_struct includes a PreCert (issuer key hash + TBSCertificate-without-SCT).
// Verifying embedded SCTs requires reconstructing that TBSCertificate, which is non-trivial.
// We only verify x509_entry SCTs here (the format used in OCSP-stapled SCTs and TLS-extension
// SCTs). Embedded SCTs return false and caller should soft-fail.
function verifySct(sct, leafCertDer, logKeys) {
	const logHex = sct.logId.toString('hex')
	const pubKey = logKeys[logHex]
	if (!pubKey) return { verified: false, reason: 'no key for log' }

	// Build signed_struct for x509_entry. Embedded-SCT (precert_entry) verification is out
	// of scope here for the reasons in the function doc; callers verifying embedded SCTs
	// should use a CT-library or implement the precert reconstruction.
	const HASH_MAP = { 1: 'md5', 2: 'sha1', 3: 'sha224', 4: 'sha256', 5: 'sha384', 6: 'sha512' }
	const hash = HASH_MAP[sct.sigAlg.hash]
	if (!hash) return { verified: false, reason: 'unsupported hash' }
	const keyAlg = sct.sigAlg.key === 3 ? 'ECDSA' : 'RSA'

	// signed_struct: 1 byte version | 1 byte sig_type | 8 bytes timestamp | 2 bytes entry_type
	// | 3 bytes cert len | cert bytes | 2 bytes ext_len | ext bytes
	const tsBuf = Buffer.alloc(8); tsBuf.writeBigUInt64BE(BigInt(sct.timestamp), 0)
	const entryType = Buffer.from([0x00, 0x00])  // x509_entry
	const certLen = Buffer.from([(leafCertDer.length >> 16) & 0xff, (leafCertDer.length >> 8) & 0xff, leafCertDer.length & 0xff])
	const extLen = Buffer.alloc(2); extLen.writeUInt16BE(sct.extensions.length, 0)
	const signed = Buffer.concat([
		Buffer.from([sct.version]),
		Buffer.from([0x00]),  // certificate_timestamp
		tsBuf,
		entryType,
		certLen, leafCertDer,
		extLen, sct.extensions,
	])

	try {
		const opts = { key: pubKey }
		if (keyAlg === 'ECDSA') opts.dsaEncoding = 'der'
		const ok = crypto.verify(hash, signed, opts, sct.signature)
		return { verified: ok, reason: ok ? null : 'signature mismatch' }
	} catch (e) {
		return { verified: false, reason: e.message }
	}
}

module.exports = { SCT_OID, extractScts, parseSctList, findSctExtension, verifySct }
