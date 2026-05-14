// Observability hooks. EventEmitter exposing lifecycle events that production callers
// need for SLO tracking, distributed tracing, and metrics.
//
// Usage:
//   const request = require('@conorre/hellojs')
//   request.observability.on('request:start', (ev) => { ... })
//   request.observability.on('handshake:end', (ev) => { ... })
//
// Events:
//   request:start    { id, method, url, headers, body? }
//   dns:start        { id, host }
//   dns:end          { id, host, addresses, durationMs }
//   connect:start    { id, host, port, family }       (TCP connect)
//   connect:end      { id, host, durationMs, error? }
//   handshake:start  { id, host, alpn? }              (TLS)
//   handshake:end    { id, host, version, cipher, alpn, durationMs, error? }
//   request:headersSent  { id, method, path }
//   request:firstByte    { id, durationMs }
//   request:end          { id, status, headers, totalBytes, durationMs }
//   request:error        { id, code, message, durationMs }
//   retry                { id, attempt, reason }
//
// Hooks are best-effort: emitting failures are logged but do NOT affect the request flow.

const { EventEmitter } = require('node:events')

class ObservabilityEmitter extends EventEmitter {
	constructor() {
		super()
		// Default max listeners is 10; production users with multiple observers will trip this.
		this.setMaxListeners(50)
	}
	safeEmit(evt, payload) {
		try { super.emit(evt, payload) } catch (_) { /* never fail the request because a hook threw */ }
	}
}

const observability = new ObservabilityEmitter()

let _nextId = 1
function nextRequestId() { return _nextId++ }

module.exports = { observability, nextRequestId }
