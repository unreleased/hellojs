// RFC 8305 Happy Eyeballs v2 for TCP connect.
//
// Why this exists: Node's default net.connect resolves the host via dns.lookup which the
// OS handles however it wants — often AAAA first, falling back to A only on failure. On a
// broken-IPv6 network (common on home Wi-Fi, hotel networks) this adds the full TCP SYN
// timeout to every connect. RFC 8305 races IPv4 + IPv6 connect attempts in parallel with
// a 250ms head start for IPv6, and accepts the first socket to complete the handshake.
//
// Usage:
//   const { happyConnect } = require('./happy-eyeballs')
//   const socket = await happyConnect({ host, port, connectTimeoutMs })

const net = require('node:net')
const dns = require('node:dns')

const HEAD_START_MS = 250

function isLiteralIp(host) {
	return net.isIP(host) > 0
}

// `hints` carries pre-resolved addresses from the HTTPS/SVCB bootstrap path (ipv4hint /
// ipv6hint). When both families are hinted we skip the DNS round-trip entirely; partial
// hints fill in the missing family from system DNS. This keeps the bootstrap-driven
// connect race aligned with the same names the published ECHConfig was selected for.
async function resolveBoth(host, hints = null) {
	if (isLiteralIp(host)) {
		const family = net.isIP(host)
		return { v6: family === 6 ? [host] : [], v4: family === 4 ? [host] : [] }
	}
	const hintedV6 = hints?.v6?.length ? hints.v6 : null
	const hintedV4 = hints?.v4?.length ? hints.v4 : null
	if (hintedV6 && hintedV4) {
		return { v6: hintedV6, v4: hintedV4 }
	}
	const v6 = hintedV6 || dns.promises.resolve6(host).catch(() => [])
	const v4 = hintedV4 || dns.promises.resolve4(host).catch(() => [])
	const [vv6, vv4] = await Promise.all([v6, v4])
	return { v6: vv6, v4: vv4 }
}


function attemptConnect(addr, port, timeoutMs) {
	return new Promise((resolve, reject) => {
		const s = net.createConnection({ host: addr, port, family: net.isIP(addr) === 6 ? 6 : 4 })
		const t = setTimeout(() => {
			s.destroy(new Error(`connect timed out (${addr}:${port})`))
		}, timeoutMs).unref?.()
		s.once('connect', () => { clearTimeout(t); resolve(s) })
		s.once('error', (e) => { clearTimeout(t); reject(e) })
	})
}

// Connect to `host:port` using happy-eyeballs v2. Returns the first socket whose 3WHS
// completes; cancels all other attempts. Falls back to standard net.connect if both DNS
// families return empty.
async function happyConnect({ host, port, connectTimeoutMs = 5000, hints = null }) {
	const { v6, v4 } = await resolveBoth(host, hints)
	if (v6.length === 0 && v4.length === 0) {
		// Last resort: let Node resolve.
		return new Promise((resolve, reject) => {
			const s = net.createConnection({ host, port })
			const t = setTimeout(() => s.destroy(new Error(`connect timed out (${host}:${port})`)), connectTimeoutMs).unref?.()
			s.once('connect', () => { clearTimeout(t); resolve(s) })
			s.once('error', (e) => { clearTimeout(t); reject(e) })
		})
	}

	// Build a prioritized list. RFC 8305 §4: interleave families, starting with v6 IF we
	// have v6 addresses; otherwise v4 fires immediately with no head-start penalty.
	const ordered = []
	for (let i = 0; i < Math.max(v6.length, v4.length); i++) {
		if (v6[i]) ordered.push(v6[i])
		if (v4[i]) ordered.push(v4[i])
	}

	// Single-address fast path — no staggering, no Promise machinery, just connect.
	// This is the common case for IP literals and for loopback (127.0.0.1 with no AAAA).
	if (ordered.length === 1) {
		return attemptConnect(ordered[0], port, connectTimeoutMs)
	}

	const haveV6 = v6.length > 0

	return new Promise((resolve, reject) => {
		const pending = new Set()
		let winner = null
		let errors = 0
		const totalAttempts = ordered.length

		const tryOne = (addr, delayMs) => {
			const start = () => {
				if (winner) return
				const p = attemptConnect(addr, port, connectTimeoutMs)
				pending.add(p)
				p.then(
					(s) => {
						if (winner) { s.destroy(); return }
						winner = s
						for (const px of pending) {
							if (px !== p) px.then((other) => other.destroy(), () => {})
						}
						resolve(s)
					},
					(_e) => {
						errors++
						pending.delete(p)
						if (!winner && errors === totalAttempts) {
							reject(new Error(`all happy-eyeballs attempts failed (host=${host}:${port})`))
						}
					},
				)
			}
			if (delayMs <= 0) start()
			else setTimeout(start, delayMs)
		}

		for (let i = 0; i < ordered.length; i++) {
			const addr = ordered[i]
			const isV4 = net.isIP(addr) === 4
			// First entry fires immediately. Subsequent entries are staggered HEAD_START_MS
			// apart. RFC 8305: if BOTH families exist, v4 attempts inherit an additional
			// HEAD_START_MS delay so v6 gets a fair head start. If only one family exists, no
			// delay applies.
			let delay = 0
			if (i > 0) delay = HEAD_START_MS * i
			if (haveV6 && isV4 && i > 0) delay += 0  // already staggered above
			tryOne(addr, delay)
		}
	})
}

module.exports = { happyConnect, resolveBoth }
