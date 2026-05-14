// hellojs error taxonomy.
//
// Every operational error eventually surfaces as a `HellojsError` with a stable
// machine-readable `.code` and a `.category` for coarse-grained handling.
// Internal `new Error(...)` throws inside parsers/protocol code get wrapped by
// the call site when they reach a user-facing boundary.
//
// Categories:
//   usage     — caller passed bad options (programmer error)
//   transport — TCP / DNS / proxy / connect-time network problem
//   tls       — TLS handshake or cert problem
//   protocol  — h1 / h2 / h3 / QUIC protocol-level failure
//   http      — HTTP status code or response framing
//   body      — request/response body stream problem
//   timeout   — any phase exceeded its budget
//
// Adding a new code? Add it to CODES, give it a category, and document it in
// README.md → "Errors".

const CATEGORY = Object.freeze({
	USAGE:     'usage',
	TRANSPORT: 'transport',
	TLS:       'tls',
	PROTOCOL:  'protocol',
	HTTP:      'http',
	BODY:      'body',
	TIMEOUT:   'timeout',
})

const CODES = Object.freeze({
	// Usage
	EBADOPTS:        { category: CATEGORY.USAGE,     msg: 'invalid request options' },
	EBADARG:         { category: CATEGORY.USAGE,     msg: 'invalid argument' },

	// Transport
	ECONNREFUSED:    { category: CATEGORY.TRANSPORT, msg: 'TCP connection refused' },
	ECONNRESET:      { category: CATEGORY.TRANSPORT, msg: 'TCP connection reset' },
	ENOTFOUND:       { category: CATEGORY.TRANSPORT, msg: 'DNS resolution failed' },
	EPROXY:          { category: CATEGORY.TRANSPORT, msg: 'proxy CONNECT failed' },

	// TLS
	ETLS_ALERT:      { category: CATEGORY.TLS,       msg: 'fatal TLS alert from server' },
	ETLS_HANDSHAKE:  { category: CATEGORY.TLS,       msg: 'TLS handshake failed' },
	ETLS_CERT_VERIFY:{ category: CATEGORY.TLS,       msg: 'server certificate chain validation failed' },
	ETLS_VERSION:    { category: CATEGORY.TLS,       msg: 'server picked an unsupported TLS version' },

	// Protocol
	EH2STREAM:       { category: CATEGORY.PROTOCOL,  msg: 'h2 stream error' },
	EH2GOAWAY:       { category: CATEGORY.PROTOCOL,  msg: 'h2 GOAWAY received' },
	EH3STREAM:       { category: CATEGORY.PROTOCOL,  msg: 'h3 stream error' },
	EH3CONN:         { category: CATEGORY.PROTOCOL,  msg: 'h3 / QUIC connection error' },
	EPROTO:          { category: CATEGORY.PROTOCOL,  msg: 'protocol-level violation' },

	// HTTP
	EHTTP:           { category: CATEGORY.HTTP,      msg: 'HTTP status >= 400 (with simple:true)' },
	EBADRESP:        { category: CATEGORY.HTTP,      msg: 'malformed HTTP response' },
	EDECOMPRESS:     { category: CATEGORY.HTTP,      msg: 'response body decompression failed' },

	// Body
	EBODYSTREAM:     { category: CATEGORY.BODY,      msg: 'request body stream error' },

	// Timeout
	ETIMEDOUT:       { category: CATEGORY.TIMEOUT,   msg: 'phase deadline exceeded' },
})

class HellojsError extends Error {
	constructor(message, code, cause) {
		super(message)
		this.name = 'HellojsError'
		this.code = code
		this.category = CODES[code]?.category ?? CATEGORY.PROTOCOL
		if (cause) this.cause = cause
	}
}

// Promote an arbitrary thrown value into a HellojsError with a best-guess code.
// Useful at user-facing boundaries where we catch unknown errors and want a
// stable shape.
function wrap(err, fallbackCode = 'EPROTO') {
	if (err instanceof HellojsError) return err
	if (!err) return new HellojsError(String(err), fallbackCode)
	// Already has a stable Node error code we recognize? Promote it.
	const nodeCode = err.code
	if (typeof nodeCode === 'string' && CODES[nodeCode]) {
		return new HellojsError(err.message || CODES[nodeCode].msg, nodeCode, err)
	}
	// Node socket codes we want to surface as-is.
	if (nodeCode === 'ECONNREFUSED' || nodeCode === 'ECONNRESET' || nodeCode === 'ENOTFOUND' || nodeCode === 'ETIMEDOUT') {
		return new HellojsError(err.message || nodeCode, nodeCode, err)
	}
	return new HellojsError(err.message || String(err), fallbackCode, err)
}

module.exports = { HellojsError, CODES, CATEGORY, wrap }
