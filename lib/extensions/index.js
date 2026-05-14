const crypto = require('crypto')

// Per RFC 8701, GREASE values are 0x0A0A, 0x1A1A, ..., 0xFA FA. Pick a random valid byte (the same byte is used twice to form the 16-bit value).
const GREASE_HIGH_NIBBLES = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
const pickGreaseByte = () => (GREASE_HIGH_NIBBLES[crypto.randomBytes(1)[0] & 0x0f] << 4) | 0x0a

// Chrome generates 3 GREASE values per connection following BoringSSL semantics:
// - greaseA: used in cipher_suites + first extension type
// - greaseB: used in supported_versions inner + last extension type
// - greaseC: used in key_share + supported_groups
// They are independently random and may collide; that's OK.
const pickGreaseTriple = () => ({
	a: pickGreaseByte(),
	b: pickGreaseByte(),
	c: pickGreaseByte(),
})

// CreateCompressCertificateExtension(algorithms?) — array of u16 algorithm codes
// (RFC 8879). Defaults to [brotli] which is what Chrome 147 sends.
const CreateCompressCertificateExtension = (algorithms = null) => {
	const codes = algorithms && algorithms.length ? algorithms : [0x0002]   // brotli
	const algBuf = Buffer.alloc(codes.length * 2)
	codes.forEach((c, i) => algBuf.writeUInt16BE(c, i * 2))
	const listLen = Buffer.alloc(1); listLen.writeUInt8(algBuf.length, 0)
	const compress_certificate = Buffer.from([0x00, 0x1b])
	const extLen = Buffer.alloc(2); extLen.writeUInt16BE(algBuf.length + 1, 0)
	return Buffer.concat([compress_certificate, extLen, listLen, algBuf])
}

const CreateGREASEExtension = (greaseValue) => {
	const grease = Buffer.from([greaseValue, greaseValue])
	const greaseLength = Buffer.alloc(2)

	const greaseExtension = Buffer.concat([grease, greaseLength])
	return greaseExtension
}

const CreateSNIExtension = (hostname) => {
	const server_name_indication = Buffer.from([0x00, 0x00])
	const server_name_type = Buffer.from([0x00])

	// Normalize + Buffer and ensure ASCII
	const hostnameBuffer = Buffer.from(
    String(hostname).trim().toLowerCase().replace(/\.$/, ''),
    'ascii'
  );

	// Get server name length
	const serverNameLength = Buffer.alloc(2)
	serverNameLength.writeUInt16BE(
		hostnameBuffer.length
	)

	const serverNameEntry = Buffer.concat([
    server_name_type,
    serverNameLength,
    hostnameBuffer,
  ]);

	// Server name list length
	const serverNameListLength = Buffer.alloc(2);
  serverNameListLength.writeUInt16BE(serverNameEntry.length, 0);

	const sniLength = Buffer.alloc(2)
  sniLength.writeUInt16BE(2 + serverNameEntry.length, 0);

	const SNI = [
    server_name_indication, // 00 00
    sniLength,              // extension_data length (N + 5)
    serverNameListLength,   // server_name_list length (N + 3)
    serverNameEntry,        // 00 | hostLen(2) | host(N)
  ]

	return Buffer.concat(SNI)
}

const CreateALPNExtension = (protocols = ['h2', 'http/1.1']) => {
	if (!Array.isArray(protocols)) protocols = [protocols]
	if (protocols.length === 0) throw new Error('ALPN: protocols array cannot be empty')
	for (const p of protocols) {
		if (typeof p !== 'string' || p.length === 0 || p.length > 255) throw new Error('ALPN: invalid protocol id ' + p)
	}

	// Generate the buffer for the ALPN
	const alpn_type = Buffer.from([0x00, 0x10])
	

	// const alpnProtocol = 
	const entries = protocols.map(p => {
    const id = Buffer.from(p, 'ascii');
    if (id.length > 255) throw new Error('ALPN id too long');
    return Buffer.concat([Buffer.from([id.length]), id]); // 1B len + bytes
  })


  const list = Buffer.concat(entries);
  const listLen = Buffer.alloc(2);
  listLen.writeUInt16BE(list.length, 0);

	const alpnLen = Buffer.alloc(2)
	alpnLen.writeUInt16BE(list.length + 2, 0) // two bytes for alpn_type

  // This is the ProtocolNameList blob that goes inside the ALPN extension
	// 02 68 32 08 68 74 74 70 2f 31 2e 31
	// 02 68 32 08 68 74 74 70 2f 31 2e 31

	const ALPN = [
		alpn_type,
		alpnLen,
		listLen,
		list
	]

	return Buffer.concat(ALPN)
}

// CreateSupportedGroupsExtension(greaseByte, supportedGroups?)
// supportedGroups is an array of u16 group codes (no GREASE). Defaults to Chrome 147.
const CreateSupportedGroupsExtension = (greaseByte = 0xEA, supportedGroups = null) => {
	const supported_groups = Buffer.from([0x00, 0x0a])
	const supportedGroupsLength = Buffer.alloc(2)

	const codes = supportedGroups && supportedGroups.length
		? supportedGroups
		: [0x11ec, 0x001d, 0x0017, 0x0018]
	const groups = [Buffer.from([greaseByte, greaseByte])]
	for (const code of codes) {
		const b = Buffer.alloc(2); b.writeUInt16BE(code, 0)
		groups.push(b)
	}

	const groupList = Buffer.concat(groups)
	const groupListLength = Buffer.alloc(2)
	groupListLength.writeUInt16BE(groupList.length, 0)

	supportedGroupsLength.writeUInt16BE(groupList.length + supported_groups.length, 0)

	const out = [
		supported_groups,
		supportedGroupsLength,
		groupListLength,
		groupList
	]

	return Buffer.concat(out)
}


const createKeyShareEntry = (group, publicRaw) => {
	const groupBuffer = Buffer.alloc(2);
	groupBuffer.writeUInt16BE(group, 0);

	const keyLen = Buffer.alloc(2);
	keyLen.writeUInt16BE(publicRaw.length, 0);

	return Buffer.concat([groupBuffer, keyLen, publicRaw]);
};

const createKeyShareExtension = (keyShareEntries) => {
	const body = Buffer.concat(keyShareEntries);
	const sharesLen = Buffer.alloc(2);
	sharesLen.writeUInt16BE(body.length, 0);

	const extBody = Buffer.concat([sharesLen, body]);

	const extType = Buffer.alloc(2);
	extType.writeUInt16BE(0x0033, 0); // Extension type for key_share

	const extLen = Buffer.alloc(2);
	extLen.writeUInt16BE(extBody.length, 0);

	return Buffer.concat([extType, extLen, extBody]);
};

// HRR path: rebuild key_share with exactly one entry for the server-requested group.
// Unlike the CH1 builder, no GREASE share — CH2 must match what HRR's key_share asked for.
const CreateKeyShareSingle = (group, publicKeyRaw) => {
	return createKeyShareExtension([createKeyShareEntry(group, publicKeyRaw)])
}

// HRR sends back a cookie the client MUST echo verbatim in CH2 (RFC 8446 §4.2.2).
const CreateCookieExtension = (cookieBytes) => {
	const ext = Buffer.from([0x00, 0x2c])
	const cookieLen = Buffer.alloc(2); cookieLen.writeUInt16BE(cookieBytes.length, 0)
	const extLen = Buffer.alloc(2);    extLen.writeUInt16BE(cookieBytes.length + 2, 0)
	return Buffer.concat([ext, extLen, cookieLen, cookieBytes])
}

// Builds the key_share extension. Caller must pre-generate the MLKEM keypair
// (since mlkem ops are async) and pass the public key in.
const CreateKeyShareX25519 = (greaseByte = 0xEA, mlkemPubKey) => {
    const { publicKey: x25519PublicKey, privateKey: x25519PrivateKey } = crypto.generateKeyPairSync('x25519')
    const spkiDerX25519 = x25519PublicKey.export({ type: 'spki', format: 'der' })
    const publicRawX25519 = spkiDerX25519.slice(-32)

    if (!mlkemPubKey || mlkemPubKey.length !== 1184) {
        throw new Error('CreateKeyShareX25519: mlkemPubKey (1184 bytes) is required')
    }
    const publicRawX25519MLKEM768 = Buffer.concat([mlkemPubKey, publicRawX25519])

    const keyShareEntryX25519 = createKeyShareEntry(0x001d, publicRawX25519)
    const keyShareEntryX25519MLKEM768 = createKeyShareEntry(0x11EC, publicRawX25519MLKEM768)
    const greaseGroup = (greaseByte << 8) | greaseByte
    const greaseKeyShare = createKeyShareEntry(greaseGroup, Buffer.from([0]))

    const extension = createKeyShareExtension([greaseKeyShare, keyShareEntryX25519MLKEM768, keyShareEntryX25519])

    return {
        extension,
        privateKey: x25519PrivateKey,
        publicRaw32: publicRawX25519,
    }
}


// CreateSignatureAlgorithmsExtension(sigalgs?) — optional override of the Chrome 147 list.
const CreateSignatureAlgorithmsExtension = (sigalgs = null) => {
	const signatureAlgorithmIds = sigalgs && sigalgs.length ? sigalgs : [
		0x0403, // ecdsa_secp256r1_sha256
		0x0804, // rsa_pss_rsae_sha256
		0x0401, // rsa_pkcs1_sha256
		0x0503, // ecdsa_secp384r1_sha384
		0x0805, // rsa_pss_rsae_sha384
		0x0501, // rsa_pkcs1_sha384
		0x0806, // rsa_pss_rsae_sha512
		0x0601, // rsa_pkcs1_sha512
	]

	const body = Buffer.alloc(2 + 2 * signatureAlgorithmIds.length)
  body.writeUInt16BE(2 * signatureAlgorithmIds.length, 0)

	let off = 2;
  for (const id of signatureAlgorithmIds) {
		body.writeUInt16BE(id, off)
		off += 2
	}

	const hdr = Buffer.alloc(4)
  hdr.writeUInt16BE(0x000d, 0)
  hdr.writeUInt16BE(body.length, 2)
  
	return Buffer.concat([hdr, body])
}

// CreateSupportedVersionsExtension(greaseByte, versions?) — versions is an array of u16
// version codes (e.g. [0x0304, 0x0303]). Defaults to TLS 1.3 + TLS 1.2.
const CreateSupportedVersionsExtension = (greaseByte = 0x0a, versions = null) => {
	const supported_versions = Buffer.from([0x00, 0x2b])

	const GREASE = Buffer.from([greaseByte, greaseByte])
	const codes = versions && versions.length ? versions : [0x0304, 0x0303]
	const verBufs = [GREASE]
	for (const c of codes) {
		const b = Buffer.alloc(2); b.writeUInt16BE(c, 0)
		verBufs.push(b)
	}

	const supportedVersionEntry = Buffer.concat(verBufs)
	const supportedVersionEntryLength = Buffer.alloc(1)
	supportedVersionEntryLength.writeUInt8(supportedVersionEntry.length, 0)


	const supportedVersionsLength = Buffer.alloc(2)
	supportedVersionsLength.writeUInt16BE(supportedVersionEntryLength.length + supportedVersionEntry.length, 0)


	const supportedVersions = [
		supported_versions,
		supportedVersionsLength,
		supportedVersionEntryLength,
		supportedVersionEntry
	]

	return Buffer.concat(supportedVersions)
}


const CreateExtendedMasterSecretExtension = () => {
	const extendedMasterSecret = Buffer.from([0x00, 0x17])
	const extendedMasterSecretLength = Buffer.alloc(2)
	extendedMasterSecretLength.writeUInt16BE(0, 0)

	return Buffer.concat([extendedMasterSecret, extendedMasterSecretLength])
}



const CreateSignedCertificateTimestampExtension = () => {
	const signed_certificate_timestamp = Buffer.from([0x00, 0x12])
	const signedCertificateTimestampLength = Buffer.alloc(2)
	signedCertificateTimestampLength.writeUInt16BE(0, 0)

	return Buffer.concat([signed_certificate_timestamp, signedCertificateTimestampLength])
}


const CreateStatusRequestExtension = () => {
	const ocspType = Buffer.from([0x01])
	const responderIdListLength = Buffer.alloc(2)
	responderIdListLength.writeUInt16BE(0, 0)

	const requestExtensionLength = Buffer.alloc(2)
	requestExtensionLength.writeUInt16BE(0, 0)

	const responderIdList = Buffer.concat([ocspType, responderIdListLength, requestExtensionLength])

	const status_request = Buffer.from([0x00, 0x05])
	const statusRequestLength = Buffer.alloc(2)
	statusRequestLength.writeUInt16BE(responderIdList.length, 0)
	
	return Buffer.concat([status_request, statusRequestLength, responderIdList])
}


const CreatePSKExchangeModesExtension = () => {
	const PSKDHE = Buffer.from([0x01])
	const PSKKeyExchangeModesLength = Buffer.alloc(1)
	PSKKeyExchangeModesLength.writeUInt8(PSKDHE.length, 0)

	const pskExchangeModes = Buffer.from([0x00, 0x2d])
	const pskExchangeModesLength = Buffer.alloc(2)
	pskExchangeModesLength.writeUInt16BE(PSKDHE.length + PSKKeyExchangeModesLength.length, 0)

	const pskExchangeModesExtension = Buffer.concat([pskExchangeModes, pskExchangeModesLength, PSKDHE, PSKKeyExchangeModesLength])
	return pskExchangeModesExtension
}

// CreateApplicationSettingsExtension(protocols?, extensionType?)
// Defaults: protocols=['h2'], extensionType=0x44cd (ALPS v1; Chrome 147 still on v1).
const CreateApplicationSettingsExtension = (protocols = null, extensionType = null) => {
	const protoList = protocols && protocols.length ? protocols : ['h2']
	const type = extensionType || 0x44cd
	const ext = Buffer.alloc(2); ext.writeUInt16BE(type, 0)

	// Each protocol: u8 length-prefixed name.
	const items = protoList.map((p) => {
		const name = Buffer.from(p, 'ascii')
		return Buffer.concat([Buffer.from([name.length]), name])
	})
	const inner = Buffer.concat(items)
	const innerLen = Buffer.alloc(2); innerLen.writeUInt16BE(inner.length, 0)
	const body = Buffer.concat([innerLen, inner])
	const bodyLen = Buffer.alloc(2); bodyLen.writeUInt16BE(body.length, 0)
	return Buffer.concat([ext, bodyLen, body])
}


const CreateEncryptedClientHelloExtension = () => {
	const ech = Buffer.from([0xfe, 0x0d])
	const echType = Buffer.from([0x00])

	const encRandomBytes = crypto.randomBytes(32)
	const randomBytes = crypto.randomBytes(240)

	const encRandomBytesLength = Buffer.alloc(2)
	encRandomBytesLength.writeUInt16BE(encRandomBytes.length, 0)

	const randomBytesLength = Buffer.alloc(2)
	randomBytesLength.writeUInt16BE(randomBytes.length, 0)

	const configId = Buffer.from([0xe9])

	const ciphers = Buffer.from([0x00, 0x01, 0x00, 0x01])

	const echLength = Buffer.alloc(2)

	echLength.writeUInt16BE(
		echType.length +
		encRandomBytes.length +
		encRandomBytesLength.length +
		randomBytes.length +
		randomBytesLength.length +
		configId.length +
		ciphers.length,
	0)


	const b = [ech, echLength, echType, ciphers, configId, encRandomBytesLength, encRandomBytes, randomBytesLength, randomBytes ]

	const echExtension = Buffer.concat(b)
	return echExtension
}

const CreateECPointFormatsExtension = () => {
	const ecPointFormats = Buffer.from([0x00, 0x0b])

	const ecPoints = Buffer.from([0x00])
	const ecPointsFormatLength = Buffer.alloc(1)
	ecPointsFormatLength.writeUInt8(ecPoints.length, 0)

	const ecPointFormatsLength = Buffer.alloc(2)
	ecPointFormatsLength.writeUInt16BE(ecPoints.length + ecPointsFormatLength.length, 0)

	const ecPointFormatsExtension = Buffer.concat([ecPointFormats, ecPointFormatsLength, ecPointsFormatLength, ecPoints])
	return ecPointFormatsExtension
}


const CreateRenegotationExtension = () => {
	const renegotation = Buffer.from([0xff, 0x01])
	const renegotationInfo = Buffer.from([0x00])
	const renegotationInfoLength = Buffer.alloc(2)
	renegotationInfoLength.writeUInt16BE(renegotationInfo.length, 0)

	const renegotationExtension = Buffer.concat([renegotation, renegotationInfoLength, renegotationInfo])
	return renegotationExtension
}

// pre_shared_key extension (0x0029) — RFC 8446 §4.2.11. MUST be the last extension in CH.
// We build it in two passes: first with binder bytes zeroed (the caller computes the binder
// after Hash(CH1_truncated)), then patches them in via patchPSKBinder() below.
//
// For now we support exactly one identity (matches our single-session-per-host cache).
//
// Wire format:
//   identities<7..2^16-1>: each = { opaque ticket<1..2^16-1>, uint32 obfuscated_ticket_age }
//   binders<33..2^16-1>:    each = opaque binder<32..255>  (32 for SHA-256, 48 for SHA-384)
const CreatePreSharedKeyExtension = (ticket, obfuscatedTicketAge, binderLen) => {
	// identities entry: 2-byte ticket length + ticket bytes + 4-byte obfuscated_ticket_age
	const idLen = Buffer.alloc(2); idLen.writeUInt16BE(ticket.length, 0)
	const ageBuf = Buffer.alloc(4); ageBuf.writeUInt32BE(obfuscatedTicketAge >>> 0, 0)
	const idEntry = Buffer.concat([idLen, ticket, ageBuf])
	const identitiesLen = Buffer.alloc(2); identitiesLen.writeUInt16BE(idEntry.length, 0)

	// binders entry: 1-byte binder length + N zero bytes (filled in later)
	const binderLenByte = Buffer.from([binderLen])
	const binderBytes = Buffer.alloc(binderLen, 0)
	const bindersInner = Buffer.concat([binderLenByte, binderBytes])
	const bindersLen = Buffer.alloc(2); bindersLen.writeUInt16BE(bindersInner.length, 0)

	const body = Buffer.concat([identitiesLen, idEntry, bindersLen, bindersInner])
	const extType = Buffer.from([0x00, 0x29])
	const extLen = Buffer.alloc(2); extLen.writeUInt16BE(body.length, 0)
	return Buffer.concat([extType, extLen, body])
}

// early_data extension (0x002a) — RFC 8446 §4.2.10. Empty body when offered in CH.
const CreateEarlyDataExtension = () => {
	return Buffer.from([0x00, 0x2a, 0x00, 0x00])
}

// Compute the byte length of the binders blob inside a pre_shared_key extension (so we
// know where to truncate CH1 when computing the binder HMAC, and where to patch the binder
// back in afterwards). One identity, binderLen-byte binder:
//   bindersList length (2) + entry length prefix (1) + binder (binderLen) = 3 + binderLen
const PSK_BINDER_BLOB_LEN = (binderLen) => 2 + 1 + binderLen

// padding extension (RFC 7685, id 21). Body is `length` zero bytes. Safari emits this with
// a length tuned so the ClientHello reaches a target wire size; Chrome 147 omits it because
// the MLKEM key_share already pushes CH past the size threshold.
const CreatePaddingExtension = (length = 0) => {
	const hdr = Buffer.from([0x00, 0x15])
	const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16BE(length, 0)
	return Buffer.concat([hdr, lenBuf, Buffer.alloc(length, 0)])
}

const createSessionTicketExtension = () => {
	const sessionTicket = Buffer.from([0x00, 0x23])
	const sessionTicketLength = Buffer.alloc(2)
	sessionTicketLength.writeUInt16BE(0, 0)

	const sessionTicketExtension = Buffer.concat([sessionTicket, sessionTicketLength])
	return sessionTicketExtension
}

module.exports = {
	CreateSNIExtension,
	CreateALPNExtension,
	CreateSupportedGroupsExtension,
	CreateKeyShareX25519,
	CreateKeyShareSingle,
	CreateCookieExtension,
	CreatePreSharedKeyExtension,
	CreateEarlyDataExtension,
	PSK_BINDER_BLOB_LEN,
	CreateSignatureAlgorithmsExtension,
	CreateSupportedVersionsExtension,
	CreateGREASEExtension,
	CreateCompressCertificateExtension,
	CreateExtendedMasterSecretExtension,
	CreateSignedCertificateTimestampExtension,
	CreateStatusRequestExtension,
	CreatePSKExchangeModesExtension,
	CreateApplicationSettingsExtension,
	CreateEncryptedClientHelloExtension,
	CreateECPointFormatsExtension,
	CreateRenegotationExtension,
	createSessionTicketExtension,
	CreatePaddingExtension,
	pickGreaseByte,
	pickGreaseTriple,
}