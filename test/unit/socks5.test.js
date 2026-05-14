// SOCKS5 client: end-to-end against a local fake SOCKS5 server.

const test = require('node:test')
const assert = require('node:assert')
const net = require('node:net')
const { socks5Connect } = require('../../lib/socks5')

// Spin up a minimal in-process SOCKS5 server that:
//   - accepts 0x00 (no-auth) and 0x02 (userpass)
//   - on CONNECT, dials a local upstream and bridges
function startFakeSocksServer({ requireUserPass = false, creds = null } = {}) {
	return new Promise((resolve) => {
		const upstream = net.createServer((c) => {
			c.on('data', (d) => c.write(Buffer.concat([Buffer.from('ECHO:'), d])))
		})
		upstream.listen(0, '127.0.0.1', () => {
			const upstreamPort = upstream.address().port

			const sock5 = net.createServer((c) => {
				let buf = Buffer.alloc(0)
				let state = 'greeting'
				c.on('data', (chunk) => {
					buf = Buffer.concat([buf, chunk])
					while (true) {
						if (state === 'greeting') {
							if (buf.length < 2) return
							const n = buf[1]
							if (buf.length < 2 + n) return
							const methods = Array.from(buf.subarray(2, 2 + n))
							buf = buf.subarray(2 + n)
							if (requireUserPass) {
								if (!methods.includes(0x02)) { c.write(Buffer.from([0x05, 0xff])); c.end(); return }
								c.write(Buffer.from([0x05, 0x02])); state = 'auth'
							} else {
								c.write(Buffer.from([0x05, 0x00])); state = 'connect'
							}
						} else if (state === 'auth') {
							if (buf.length < 2) return
							const ulen = buf[1]; if (buf.length < 2 + ulen + 1) return
							const u = buf.subarray(2, 2 + ulen).toString()
							const plen = buf[2 + ulen]; if (buf.length < 2 + ulen + 1 + plen) return
							const p = buf.subarray(2 + ulen + 1, 2 + ulen + 1 + plen).toString()
							buf = buf.subarray(2 + ulen + 1 + plen)
							if (creds && (u !== creds.u || p !== creds.p)) { c.write(Buffer.from([0x01, 0x01])); c.end(); return }
							c.write(Buffer.from([0x01, 0x00])); state = 'connect'
						} else if (state === 'connect') {
							if (buf.length < 5) return
							const atyp = buf[3]
							let total = 4 + 2  // BND.PORT
							if (atyp === 0x01) total += 4
							else if (atyp === 0x04) total += 16
							else if (atyp === 0x03) total += 1 + buf[4]
							if (buf.length < total) return
							buf = buf.subarray(total)
							// Always bridge to our upstream regardless of requested address.
							const target = net.createConnection({ host: '127.0.0.1', port: upstreamPort }, () => {
								c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
								c.pipe(target); target.pipe(c)
							})
							return
						}
					}
				})
			})
			sock5.listen(0, '127.0.0.1', () => {
				resolve({ sock5, upstream, port: sock5.address().port, upstreamPort, close: () => { sock5.close(); upstream.close() } })
			})
		})
	})
}

test('SOCKS5 no-auth: connect + bridge', { timeout: 5000 }, async () => {
	const srv = await startFakeSocksServer()
	const sock = await socks5Connect({
		proxyHost: '127.0.0.1', proxyPort: srv.port,
		destHost: 'unused.example.com', destPort: 1234,
		connectTimeoutMs: 1000,
	})
	sock.write('hello')
	const got = await new Promise((r) => sock.once('data', r))
	assert.strictEqual(got.toString(), 'ECHO:hello')
	sock.destroy()
	srv.close()
})

test('SOCKS5 user/pass: correct creds succeed, wrong creds fail', { timeout: 5000 }, async () => {
	const srv = await startFakeSocksServer({ requireUserPass: true, creds: { u: 'alice', p: 'secret' } })
	const sock = await socks5Connect({
		proxyHost: '127.0.0.1', proxyPort: srv.port,
		username: 'alice', password: 'secret',
		destHost: 'unused.example.com', destPort: 1234,
		connectTimeoutMs: 1000,
	})
	sock.write('hi')
	const got = await new Promise((r) => sock.once('data', r))
	assert.strictEqual(got.toString(), 'ECHO:hi')
	sock.destroy()

	await assert.rejects(
		socks5Connect({
			proxyHost: '127.0.0.1', proxyPort: srv.port,
			username: 'alice', password: 'wrong',
			destHost: 'unused.example.com', destPort: 1234,
			connectTimeoutMs: 1000,
		}),
		(e) => /authentication failed/.test(e.message),
	)
	srv.close()
})
