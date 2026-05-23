// HTTPS/SVCB bootstrap for ECH.
//
// Given an origin name, this module resolves HTTPS (and, when needed, SVCB) records,
// follows AliasMode chains, filters out endpoints we cannot honor, and returns the
// connect/public-name/address-hint metadata the transport layer needs.
//
// The output is transport-agnostic: TCP/TLS and QUIC both consume the same bootstrap
// result so ECH config selection, connect-name routing, and address hints stay aligned.
const { buildQuery, parseResponse, sendDnsQuery } = require('./wire')

const MAX_ALIAS_HOPS = 8
const SUPPORTED_MANDATORY = new Set([
	'mandatory',
	'alpn',
	'noDefaultAlpn',
	'port',
	'ipv4hint',
	'echConfigList',
	'ipv6hint',
])

const RCODE_NAMES = {
	1: 'FORMERR',
	2: 'SERVFAIL',
	3: 'NXDOMAIN',
	4: 'NOTIMP',
	5: 'REFUSED',
}

function parseHttpsResponse(buf) {
	const msg = parseResponse(buf)
	if (!msg.isResponse) throw new Error('invalid DNS response: QR bit not set')
	if (msg.rcode !== 0) {
		const ownerName = msg.questions[0]?.name || 'unknown host'
		const rcode = RCODE_NAMES[msg.rcode] || `RCODE ${msg.rcode}`
		throw new Error(`DNS lookup failed for ${ownerName}: ${rcode}`)
	}
	const ownerName = msg.questions[0]?.name?.toLowerCase() || null
	const answers = msg.answers.filter((rr) => (rr.type === 'HTTPS' || rr.type === 'SVCB') && (!ownerName || rr.name.toLowerCase() === ownerName))
	const aliasMode = answers.filter((rr) => rr.priority === 0)
	const serviceMode = answers.filter((rr) => rr.priority > 0)
	if (aliasMode.length > 0 && serviceMode.length > 0) {
		throw new Error(`invalid HTTPS/SVCB RRSet for ${msg.questions[0]?.name || 'unknown host'}: mixed alias and service mode records`)
	}
	return { aliasMode, serviceMode }
}

function chooseHttpsEndpoint(rrset) {
	if (!rrset) return null
	const usableServiceMode = rrset.serviceMode
		.filter((rr) => hasSupportedMandatory(rr.params))
		.sort((a, b) => a.priority - b.priority)
	const winner = usableServiceMode[0] || null
	if (!winner) return null
	const allHaveEch = usableServiceMode.length > 0 && usableServiceMode.every((rr) => Buffer.isBuffer(rr.params.echConfigList))
	return {
		svcbReliant: allHaveEch,
		targetName: winner.targetName === '.' ? null : winner.targetName,
		port: winner.params.port || null,
		alpn: winner.params.alpn || [],
		noDefaultAlpn: winner.params.noDefaultAlpn === true,
		ipv4hint: winner.params.ipv4hint || [],
		ipv6hint: winner.params.ipv6hint || [],
		echConfigList: winner.params.echConfigList || null,
		mandatory: winner.params.mandatory || [],
	}
}

function normalizeDnsName(name) {
	if (!name || name === '.') return '.'
	return name.endsWith('.') ? name.slice(0, -1) : name
}

async function resolveHttpsRecords(host, { resolver = sendDnsQuery, maxAliasHops = MAX_ALIAS_HOPS } = {}) {
	const publicName = normalizeDnsName(host)
	let currentHost = publicName
	const seen = new Set()
	for (let hop = 0; hop <= maxAliasHops; hop++) {
		if (seen.has(currentHost)) return null
		seen.add(currentHost)
		let rrset = parseHttpsResponse(await resolver(buildQuery(currentHost, 'HTTPS')))
		if (rrset.aliasMode.length === 0 && rrset.serviceMode.length === 0) {
			try {
				rrset = parseHttpsResponse(await resolver(buildQuery(currentHost, 'SVCB')))
			} catch (err) {
				if (/^DNS lookup failed for .*: (NOTIMP|REFUSED)$/.test(String(err?.message || ''))) return null
				throw err
			}
		}
		const endpoint = chooseHttpsEndpoint(rrset)
		if (endpoint) {
			return {
				...endpoint,
				publicName,
				ownerName: currentHost,
				connectName: normalizeDnsName(endpoint.targetName || currentHost),
			}
		}
		const alias = chooseAliasTarget(rrset)
		if (!alias) return null
		currentHost = normalizeDnsName(alias)
	}
	return null
}

function chooseAliasTarget(rrset) {
	if (!rrset || rrset.aliasMode.length === 0) return null
	for (const record of rrset.aliasMode) {
		if (record.targetName && record.targetName !== '.') return record.targetName
	}
	return null
}

function hasSupportedMandatory(params = {}) {
	const mandatory = params.mandatory || []
	for (const key of mandatory) {
		if (!SUPPORTED_MANDATORY.has(key)) return false
		if (!(key in params)) return false
	}
	return true
}

module.exports = { parseHttpsResponse, chooseHttpsEndpoint, resolveHttpsRecords }
