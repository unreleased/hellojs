// SOCKS5 client per RFC 1928 + RFC 1929 (user/pass auth).
//
// Usage:
//   const sock = await socks5Connect({
//     proxyHost: 'proxy.example.com',
//     proxyPort: 1080,
//     username, password,                // optional
//     destHost: 'target.example.com',
//     destPort: 443,
//     connectTimeoutMs: 10_000,
//   })
//
// Returns a connected Node net.Socket whose payload is the tunneled stream — feed it to
// the TLS layer the same way you would a direct net.createConnection result.
//
// Limitations:
//   - No GSSAPI auth (method 0x01) — only no-auth (0x00) and userpass (0x02).
//   - IPv4 / IPv6 / domain-name address types (0x01, 0x04, 0x03) all supported on the request side.

const net = require('node:net')

function buildAuthRequest(username, password) {
	// RFC 1929: VER=0x01, ULEN, UNAME, PLEN, PASSWD
	const u = Buffer.from(username, 'utf8')
	const p = Buffer.from(password, 'utf8')
	return Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p])
}

function buildConnectRequest(destHost, destPort) {
	// RFC 1928 §4: VER=0x05, CMD=CONNECT(0x01), RSV=0x00, ATYP, DST.ADDR, DST.PORT
	let atyp, addr
	const ipFamily = net.isIP(destHost)
	if (ipFamily === 4) {
		atyp = 0x01
		addr = Buffer.from(destHost.split('.').map(n => parseInt(n, 10)))
	} else if (ipFamily === 6) {
		atyp = 0x04
		const parts = destHost.split(':')
		// Expand "::" — simplest: rely on the standard form for now
		const groups = parts.length === 8 ? parts : null
		if (!groups) throw new Error('SOCKS5: complex IPv6 (::-shortened) not supported here')
		const buf = Buffer.alloc(16)
		groups.forEach((g, i) => { const v = parseInt(g || '0', 16); buf.writeUInt16BE(v, i * 2) })
		addr = buf
	} else {
		atyp = 0x03
		const name = Buffer.from(destHost, 'utf8')
		addr = Buffer.concat([Buffer.from([name.length]), name])
	}
	const portBuf = Buffer.alloc(2); portBuf.writeUInt16BE(destPort, 0)
	return Buffer.concat([Buffer.from([0x05, 0x01, 0x00, atyp]), addr, portBuf])
}

function readReply(buf) {
	// SOCKS5 reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	if (buf.length < 7) return null   // need at least ATYP byte to know length
	const ver = buf[0]
	const rep = buf[1]
	const atyp = buf[3]
	let bndLen
	if (atyp === 0x01) bndLen = 4
	else if (atyp === 0x04) bndLen = 16
	else if (atyp === 0x03) {
		if (buf.length < 5) return null
		bndLen = 1 + buf[4]
	} else return { error: `unknown ATYP ${atyp}` }
	const total = 4 + bndLen + 2
	if (buf.length < total) return null
	return { ver, rep, consumed: total }
}

function socks5Connect({ proxyHost, proxyPort, username, password, destHost, destPort, connectTimeoutMs = 10_000 }) {
	return new Promise((resolve, reject) => {
		const sock = net.createConnection({ host: proxyHost, port: proxyPort })
		const t = setTimeout(() => { sock.destroy(new Error('SOCKS5 connect timed out')) }, connectTimeoutMs)
		let buf = Buffer.alloc(0)
		let state = 'greeting'   // greeting -> auth (optional) -> connect -> done

		const fail = (err) => { clearTimeout(t); try { sock.destroy() } catch (_) {}; reject(err) }

		sock.once('error', (e) => fail(e))

		sock.on('data', (chunk) => {
			buf = Buffer.concat([buf, chunk])
			while (true) {
				if (state === 'greeting') {
					if (buf.length < 2) return
					const ver = buf[0], method = buf[1]
					buf = buf.subarray(2)
					if (ver !== 0x05) return fail(new Error(`SOCKS5: unexpected greeting version ${ver}`))
					if (method === 0xFF) return fail(new Error('SOCKS5: no acceptable auth methods'))
					if (method === 0x00) { state = 'connect'; sock.write(buildConnectRequest(destHost, destPort)) }
					else if (method === 0x02) {
						if (!username) return fail(new Error('SOCKS5: server requires user/pass auth but none given'))
						state = 'auth'
						sock.write(buildAuthRequest(username, password || ''))
					} else { return fail(new Error(`SOCKS5: unsupported method 0x${method.toString(16)}`)) }
				} else if (state === 'auth') {
					if (buf.length < 2) return
					const ver = buf[0], status = buf[1]
					buf = buf.subarray(2)
					if (ver !== 0x01) return fail(new Error(`SOCKS5 auth: unexpected version ${ver}`))
					if (status !== 0x00) return fail(new Error('SOCKS5: user/pass authentication failed'))
					state = 'connect'
					sock.write(buildConnectRequest(destHost, destPort))
				} else if (state === 'connect') {
					const reply = readReply(buf)
					if (!reply) return
					if (reply.error) return fail(new Error(`SOCKS5 reply: ${reply.error}`))
					if (reply.ver !== 0x05) return fail(new Error(`SOCKS5 reply: unexpected version ${reply.ver}`))
					if (reply.rep !== 0x00) {
						const codes = { 1: 'general failure', 2: 'connection not allowed', 3: 'network unreachable',
							4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
							7: 'command not supported', 8: 'address type not supported' }
						return fail(new Error(`SOCKS5 connect failed: ${codes[reply.rep] || `code ${reply.rep}`}`))
					}
					// Tunnel established. Anything in `buf` past `reply.consumed` is real stream data.
					clearTimeout(t)
					const leftover = buf.subarray(reply.consumed)
					sock.removeAllListeners('data')
					sock.removeAllListeners('error')
					if (leftover.length) sock.unshift(leftover)
					resolve(sock)
					return
				}
			}
		})

		sock.once('connect', () => {
			// Greeting: VER=5, NMETHODS, METHODS[]
			// Offer 0x00 (no auth) and 0x02 (user/pass) if creds supplied; otherwise just no-auth.
			const methods = username ? [0x00, 0x02] : [0x00]
			sock.write(Buffer.from([0x05, methods.length, ...methods]))
		})
	})
}

module.exports = { socks5Connect, buildConnectRequest, buildAuthRequest, readReply }
