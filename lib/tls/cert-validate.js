// Server certificate chain validation (RFC 5280, RFC 6125).
//
// Walks the cert chain leaf → intermediates → trusted root. For each link:
//   - issuer of cert[i] matches subject of cert[i+1]
//   - cert[i]'s signature verifies against cert[i+1]'s pubkey
//   - Date.now() is within notBefore/notAfter
// The leaf's hostname is validated against Subject Alternative Name (or fall back to CN).
// The chain must terminate in a cert present in Node's bundled root CAs.

const crypto = require('crypto')
const tls = require('tls')

let _trustedRoots = null   // [{cert: X509Certificate, subject, issuer, fingerprint256}]
function trustedRoots() {
	if (_trustedRoots) return _trustedRoots
	_trustedRoots = []
	for (const pem of tls.rootCertificates) {
		try {
			const c = new crypto.X509Certificate(pem)
			_trustedRoots.push(c)
		} catch (_) { /* skip unparseable */ }
	}
	return _trustedRoots
}

// Match a leaf cert against a hostname per RFC 6125.
function hostnameMatches(cert, hostname) {
	const host = String(hostname).toLowerCase()
	// Subject Alternative Name (DNS:) — modern path, what browsers use.
	const san = cert.subjectAltName || ''
	for (const part of san.split(',')) {
		const trimmed = part.trim()
		if (trimmed.startsWith('DNS:')) {
			const pattern = trimmed.slice(4).toLowerCase()
			if (matchHostname(pattern, host)) return true
		}
		if (trimmed.startsWith('IP Address:')) {
			if (trimmed.slice(11).trim() === host) return true
		}
	}
	// If SAN didn't match (or didn't exist), the cert is invalid for this hostname.
	// CN-only matching is deprecated by RFC 6125 §6.4.4 and rejected by Chrome since 2017.
	return false
}

function matchHostname(pattern, host) {
	if (pattern === host) return true
	// Wildcard: *.example.com matches foo.example.com but not example.com or foo.bar.example.com
	if (pattern.startsWith('*.')) {
		const suffix = pattern.slice(1)   // includes the leading "."
		const dot = host.indexOf('.')
		if (dot < 0) return false
		const hostSuffix = host.slice(dot)
		return hostSuffix === suffix
	}
	return false
}

// Validate the chain against the trust store. Returns { ok, reason }.
// Chain order: leaf, intermediate1, intermediate2, ... (server-supplied order).
function validateChain(chainDerOrCerts, hostname, { now = Date.now() } = {}) {
	const chain = chainDerOrCerts.map(x => x instanceof crypto.X509Certificate ? x : new crypto.X509Certificate(x))
	if (chain.length === 0) return { ok: false, reason: 'empty chain' }
	const leaf = chain[0]

	// Validity window
	for (let i = 0; i < chain.length; i++) {
		const c = chain[i]
		const nb = Date.parse(c.validFrom)
		const na = Date.parse(c.validTo)
		if (now < nb) return { ok: false, reason: `cert[${i}] not yet valid (notBefore=${c.validFrom})` }
		if (now > na) return { ok: false, reason: `cert[${i}] expired (notAfter=${c.validTo})` }
	}

	// Hostname match on leaf
	if (!hostnameMatches(leaf, hostname)) {
		return { ok: false, reason: `leaf cert does not match hostname "${hostname}" (subjectAltName=${leaf.subjectAltName || '(none)'})` }
	}

	// Walk the chain bottom-up. At each cert, first try to terminate the path: does the
	// trust store contain a root whose subject matches this cert's issuer AND whose pubkey
	// verifies this cert's signature? If yes, we've found a valid path — accept the chain
	// regardless of what's above. This handles servers that send a retired self-signed root
	// at the top (e.g. Amazon's VeriSign G5) but where an intermediate is signed by a root
	// still in our trust store.
	const roots = trustedRoots()
	let trustedRoot = null
	for (let i = 0; i < chain.length; i++) {
		const cert = chain[i]
		// Try to terminate the path here: find a root that issued this cert.
		const candidates = roots.filter(r => r.subject === cert.issuer)
		for (const root of candidates) {
			if (cert.verify(root.publicKey)) { trustedRoot = root; break }
		}
		if (trustedRoot) break
		// Also check: if this cert IS a trusted root itself (self-signed + in trust store).
		if (cert.issuer === cert.subject) {
			const match = roots.find(r => r.fingerprint256 === cert.fingerprint256)
			if (match) { trustedRoot = match; break }
		}
		// Otherwise verify the next cert in chain signed this one (walking up).
		const parent = chain[i + 1]
		if (!parent) break
		if (cert.issuer !== parent.subject) {
			return { ok: false, reason: `chain break: cert[${i}].issuer != cert[${i + 1}].subject` }
		}
		if (!cert.verify(parent.publicKey)) {
			return { ok: false, reason: `cert[${i}] signature does not verify against cert[${i + 1}].publicKey` }
		}
	}
	if (!trustedRoot) {
		const top = chain[chain.length - 1]
		return { ok: false, reason: `chain does not terminate in a trusted root (top issuer="${top.issuer}")` }
	}

	// Best-effort: extract embedded SCT(s) for downstream policy inspection. We don't enforce
	// here — Chrome requires CT for certs issued post-2018 but verifying SCT signatures requires
	// shipping the CT log key list, which we expose as an opt-in via tls.options.ctLogKeys.
	let scts = []
	try {
		const { extractScts } = require('./sct')
		scts = extractScts(Buffer.from(leaf.raw))
	} catch (_) { /* parse failure is non-fatal */ }

	return { ok: true, root: trustedRoot.subject, scts }
}

module.exports = { validateChain, hostnameMatches, trustedRoots }
