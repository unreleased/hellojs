// Default Chrome 147 request header set + ordering, plus the profile-driven builders that
// the client uses to assemble outgoing requests. HTTP/2 sends headers in the order keys are
// inserted into the JS object, so order is controllable from JS.

const CHROME_147_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36'

const CHROME_147_DEFAULT_HEADERS = Object.freeze({
	'sec-ch-ua': '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
	'sec-ch-ua-mobile': '?0',
	'sec-ch-ua-platform': '"macOS"',
	'upgrade-insecure-requests': '1',
	'user-agent': CHROME_147_UA,
	'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	'sec-fetch-site': 'none',
	'sec-fetch-mode': 'navigate',
	'sec-fetch-user': '?1',
	'sec-fetch-dest': 'document',
	'accept-encoding': 'gzip, deflate, br, zstd',
	'accept-language': 'en-US,en;q=0.9,es;q=0.8',
	'priority': 'u=0, i',
})

const DEFAULT_PSEUDO_ORDER = [':method', ':authority', ':scheme', ':path']

function defaultsFromProfile(profile) {
	if (profile && profile.headers) return profile.headers
	return CHROME_147_DEFAULT_HEADERS
}

function pseudoOrderFromProfile(profile) {
	const o = profile?.http2?.pseudoHeaderOrder
	return Array.isArray(o) && o.length ? o : DEFAULT_PSEUDO_ORDER
}

// Build the H/2 headers map for an outgoing request. Pseudo-headers come first in the
// profile-defined order; the profile-default header block follows in its declared order;
// caller overrides win on conflict.
function buildH2Headers({ method, host, path, userHeaders, profile }) {
	const order = pseudoOrderFromProfile(profile)
	const pseudoVals = { ':method': method, ':authority': host, ':scheme': 'https', ':path': path }
	const h = {}
	for (const k of order) {
		if (pseudoVals[k] != null) h[k] = pseudoVals[k]
	}
	// Any pseudo we know about but isn't in the profile's order — append for safety.
	for (const [k, v] of Object.entries(pseudoVals)) {
		if (h[k] == null) h[k] = v
	}
	for (const [k, v] of Object.entries(defaultsFromProfile(profile))) {
		h[k] = v
	}
	if (userHeaders) {
		for (const [k, v] of Object.entries(userHeaders)) {
			h[k.toLowerCase()] = v
		}
	}
	return h
}

// HTTP/1.1 header block builder. Returns a CRLF-joined header section (no leading request line).
function buildH1Headers({ host, userHeaders, profile }) {
	const merged = { ...defaultsFromProfile(profile) }
	if (userHeaders) for (const [k, v] of Object.entries(userHeaders)) merged[k.toLowerCase()] = v
	const lines = [`Host: ${host}`]
	for (const [k, v] of Object.entries(merged)) {
		lines.push(`${k.replace(/(^|-)([a-z])/g, (_, p, c) => p + c.toUpperCase())}: ${v}`)
	}
	return lines.join('\r\n')
}

module.exports = { CHROME_147_DEFAULT_HEADERS, CHROME_147_UA, buildH2Headers, buildH1Headers }
