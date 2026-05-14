// Signed Certificate Timestamp parser tests.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const { extractScts, parseSctList, findSctExtension } = require('../../lib/tls/sct')

test('extractScts on a cert with no SCT extension returns []', () => {
	const { execSync } = require('node:child_process')
	const fs = require('node:fs'), path = require('node:path'), os = require('node:os')
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sct-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" 2>/dev/null`)
	const cert = new crypto.X509Certificate(fs.readFileSync(c))
	const r = extractScts(cert.raw)
	fs.rmSync(dir, { recursive: true, force: true })
	assert.deepStrictEqual(r, [])
})

test('parseSctList handles a synthetic 2-SCT list', () => {
	// Build a SignedCertificateTimestampList with two SCTs.
	// Each SCT: version(1)=0 | logId(32) | timestamp(8) | extensions u16-prefixed | sigAlg(2) | sig u16-prefixed.
	function makeSct(logSeed, ts) {
		const buf = Buffer.alloc(1 + 32 + 8 + 2 + 2 + 2 + 16)
		let o = 0
		buf[o++] = 0
		Buffer.alloc(32, logSeed).copy(buf, o); o += 32
		buf.writeBigUInt64BE(BigInt(ts), o); o += 8
		buf.writeUInt16BE(0, o); o += 2   // extensions empty
		buf[o++] = 4; buf[o++] = 1        // sha256, RSA
		buf.writeUInt16BE(16, o); o += 2  // signature length
		// 16 zero bytes
		return buf
	}
	const sct1 = makeSct(0xaa, 1700000000000)
	const sct2 = makeSct(0xbb, 1700000001000)
	// Wrap each in 2-byte length, then the whole in 2-byte length.
	const inner = Buffer.concat([
		Buffer.from([(sct1.length >> 8) & 0xff, sct1.length & 0xff]), sct1,
		Buffer.from([(sct2.length >> 8) & 0xff, sct2.length & 0xff]), sct2,
	])
	const list = Buffer.concat([
		Buffer.from([(inner.length >> 8) & 0xff, inner.length & 0xff]),
		inner,
	])
	const out = parseSctList(list)
	assert.strictEqual(out.length, 2)
	assert.strictEqual(out[0].timestamp, 1700000000000)
	assert.strictEqual(out[1].timestamp, 1700000001000)
	assert.strictEqual(out[0].logId.length, 32)
	assert.strictEqual(out[0].logId[0], 0xaa)
	assert.strictEqual(out[1].logId[0], 0xbb)
})

test('findSctExtension on a real-world cert returns the extension bytes', async () => {
	// Fetch the cert from a real CT-enforced site (cloudflare.com) by opening a TLS socket.
	const tls = require('node:tls')
	await new Promise((resolve) => {
		const sock = tls.connect({ host: 'www.cloudflare.com', port: 443, servername: 'www.cloudflare.com', rejectUnauthorized: false }, () => {
			const peer = sock.getPeerX509Certificate()
			const der = Buffer.from(peer.raw)
			const ext = findSctExtension(der)
			assert.ok(ext, 'cloudflare.com cert should have an SCT extension')
			const scts = parseSctList(ext)
			assert.ok(scts.length >= 1, `expected >=1 SCT, got ${scts.length}`)
			for (const s of scts) {
				assert.strictEqual(s.logId.length, 32)
				assert.ok(s.timestamp > 0)
			}
			sock.destroy()
			resolve()
		})
		sock.on('error', () => resolve())  // skip if network is sandboxed
	})
})
