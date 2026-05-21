// Compute JA3 / JA4 hashes from a TLS ClientHello record we just put on the wire.
//
// This is the "fail loud / verify locally" side of the fingerprint engine — given the bytes
// hellojs produced, you can compare against a profile's expected.* hashes without round-tripping
// through tls.peet.ws. Useful for:
//   - CI regression: assert ja4(profile) matches profile.expected.ja4 on every build
//   - Diagnosing parrot mismatches: see exactly which field changed
//
// JA3 spec:  https://github.com/salesforce/ja3
// JA4 spec:  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
// GREASE handling (RFC 8701 §3): codepoints whose high nibble == low nibble == 0xA in both
// bytes are GREASE — they MUST be excluded from JA3 and JA4 inputs.

const crypto = require('crypto')

// 0x0a0a, 0x1a1a, 0x2a2a, … 0xfafa.
function isGrease(u16) {
	return (u16 & 0x0f0f) === 0x0a0a && ((u16 >> 8) & 0x0f) === (u16 & 0x0f)
}

// Parse a TLS record carrying a ClientHello (record header + handshake header + body).
// Returns the structural pieces JA3/JA4 need.
function parseClientHello(rec) {
	if (rec.length < 5 || rec[0] !== 0x16) throw new Error('parseClientHello: not a handshake record')
	const recLen = rec.readUInt16BE(3)
	if (rec.length < 5 + recLen) throw new Error('parseClientHello: short record')
	const hs = rec.subarray(5, 5 + recLen)
	if (hs[0] !== 0x01) throw new Error('parseClientHello: not a ClientHello')

	let o = 4
	const legacyVersion = hs.readUInt16BE(o); o += 2
	o += 32                                            // random
	const sidLen = hs[o]; o += 1 + sidLen
	const csLen = hs.readUInt16BE(o); o += 2
	const ciphers = []
	for (let i = 0; i < csLen; i += 2) ciphers.push(hs.readUInt16BE(o + i))
	o += csLen
	const cmLen = hs[o]; o += 1 + cmLen
	const extsLen = hs.readUInt16BE(o); o += 2
	const extEnd = o + extsLen
	const extensions = []     // [{ id, body }] in wire order
	const extMap = {}
	while (o < extEnd) {
		const id = hs.readUInt16BE(o); o += 2
		const len = hs.readUInt16BE(o); o += 2
		const body = hs.subarray(o, o + len)
		extensions.push({ id, body })
		extMap[id] = body
		o += len
	}

	// supported_versions (43): highest non-GREASE version, or legacy_version if no ext.
	let chosenVersion = legacyVersion
	if (extMap[43]) {
		const sv = extMap[43]
		const listLen = sv[0]
		let highest = 0
		for (let i = 0; i < listLen; i += 2) {
			const v = sv.readUInt16BE(1 + i)
			if (!isGrease(v) && v > highest) highest = v
		}
		if (highest) chosenVersion = highest
	}

	// supported_groups (10)
	const groups = []
	if (extMap[10]) {
		const sg = extMap[10]
		const listLen = sg.readUInt16BE(0)
		for (let i = 0; i < listLen; i += 2) groups.push(sg.readUInt16BE(2 + i))
	}

	// ec_point_formats (11)
	const ecPointFormats = []
	if (extMap[11]) {
		const ec = extMap[11]
		const listLen = ec[0]
		for (let i = 0; i < listLen; i++) ecPointFormats.push(ec[1 + i])
	}

	// signature_algorithms (13)
	const sigalgs = []
	if (extMap[13]) {
		const sa = extMap[13]
		const listLen = sa.readUInt16BE(0)
		for (let i = 0; i < listLen; i += 2) sigalgs.push(sa.readUInt16BE(2 + i))
	}

	// ALPN (16)
	let alpnFirst = null
	if (extMap[16]) {
		const al = extMap[16]
		const listLen = al.readUInt16BE(0)
		if (listLen >= 1) {
			const nameLen = al[2]
			if (nameLen) alpnFirst = al.subarray(3, 3 + nameLen).toString('ascii')
		}
	}

	const sni = !!extMap[0]

	return { legacyVersion, chosenVersion, ciphers, extensions, extMap, groups, ecPointFormats, sigalgs, alpnFirst, sni }
}

// JA3 = MD5("version,ciphers,extensions,groups,point_formats"), GREASE excluded.
function ja3(ch) {
	const ver = ch.legacyVersion
	const ciphers = ch.ciphers.filter(c => !isGrease(c)).join('-')
	const exts = ch.extensions.filter(e => !isGrease(e.id)).map(e => e.id).join('-')
	const groups = ch.groups.filter(g => !isGrease(g)).join('-')
	const points = ch.ecPointFormats.join('-')
	const str = `${ver},${ciphers},${exts},${groups},${points}`
	return { str, hash: crypto.createHash('md5').update(str).digest('hex') }
}

// JA4 = "t<ver>d<#ciphers><#extensions><alpn>_<sha256(ciphers-sorted)>:12_<sha256(extensions-sorted-w/o-sni-or-alpn,sig_algs)>:12"
// Per the FoxIO spec — see the doc linked at the top.
function ja4(ch) {
	const protoChar = 't'                                   // tcp (we don't run quic from this path)
	let verCode
	switch (ch.chosenVersion) {
		case 0x0304: verCode = '13'; break
		case 0x0303: verCode = '12'; break
		case 0x0302: verCode = '11'; break
		case 0x0301: verCode = '10'; break
		default:     verCode = '00'
	}
	const sniChar = ch.sni ? 'd' : 'i'
	const ciphersNoGrease = ch.ciphers.filter(c => !isGrease(c))
	const cipherCount = String(ciphersNoGrease.length).padStart(2, '0')
	const extsNoGrease = ch.extensions.filter(e => !isGrease(e.id)).map(e => e.id)
	const extCount = String(extsNoGrease.length).padStart(2, '0')
	let alpnTag = '00'
	if (ch.alpnFirst && ch.alpnFirst.length >= 1) {
		const first = ch.alpnFirst[0]
		const last = ch.alpnFirst[ch.alpnFirst.length - 1]
		alpnTag = `${first}${last}`
	}
	const ja4_a = `${protoChar}${verCode}${sniChar}${cipherCount}${extCount}${alpnTag}`

	const cipherHex = (n) => n.toString(16).padStart(4, '0')
	const sortedCiphers = ciphersNoGrease.slice().sort((a, b) => a - b).map(cipherHex).join(',')
	const ja4_b = crypto.createHash('sha256').update(sortedCiphers).digest('hex').slice(0, 12)

	// JA4_c: extensions sorted, EXCLUDING SNI (0) and ALPN (16). Then a comma, then the
	// signature_algorithms list IN WIRE ORDER.
	const extsForC = extsNoGrease.filter(id => id !== 0 && id !== 16).slice().sort((a, b) => a - b).map(cipherHex)
	const sigPart = ch.sigalgs.map(cipherHex).join(',')
	const ja4_c = crypto.createHash('sha256')
		.update(`${extsForC.join(',')}_${sigPart}`)
		.digest('hex').slice(0, 12)

	return { str: `${ja4_a}_${ja4_b}_${ja4_c}`, ja4_a, ja4_b, ja4_c }
}

module.exports = { parseClientHello, ja3, ja4, isGrease }
