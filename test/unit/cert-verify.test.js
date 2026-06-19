// Tier-1 TLS authentication fixes:
//   - validateChain enforces basicConstraints CA:TRUE on issuers (no leaf-as-CA forgery)
//   - verifyCertVerify checks the TLS 1.3 server CertificateVerify signature (RFC 8446 §4.4.3)
//   - parseCertificateList parses/round-trips the Certificate message (also via the compressed path)

const test = require('node:test')
const assert = require('node:assert')
const { after } = require('node:test')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const zlib = require('node:zlib')
const { execSync } = require('node:child_process')
const { validateChain, trustedRoots, verifyCertVerify, parseCertificateList } = require('../../lib/tls/cert-validate')

const D = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcv-'))
const sh = (cmd) => execSync(cmd, { cwd: D, stdio: ['ignore', 'ignore', 'ignore'] })
const eckey = (n) => sh(`openssl ecparam -name prime256v1 -genkey -noout -out ${n}`)
const der = (crt) => Buffer.from(new crypto.X509Certificate(fs.readFileSync(path.join(D, crt))).raw)
const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
const writeExt = (n, s) => fs.writeFileSync(path.join(D, n), s)

// Build a small PKI: root CA -> intermediate CA -> good leaf; plus a non-CA "attacker" leaf signed
// by the root, and a forged victim cert signed with the attacker leaf's (non-CA) key.
eckey('root.key')
sh(`openssl req -x509 -new -key root.key -out root.crt -days 2 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE"`)
eckey('int.key')
sh(`openssl req -new -key int.key -out int.csr -subj "/CN=Test Intermediate"`)
writeExt('int.ext', 'basicConstraints=critical,CA:TRUE\n')
sh(`openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 2 -extfile int.ext`)
eckey('good.key')
sh(`openssl req -new -key good.key -out good.csr -subj "/CN=good.example"`)
writeExt('good.ext', 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:good.example\n')
sh(`openssl x509 -req -in good.csr -CA int.crt -CAkey int.key -CAcreateserial -out good.crt -days 2 -extfile good.ext`)
eckey('att.key')
sh(`openssl req -new -key att.key -out att.csr -subj "/CN=attacker.example"`)
writeExt('att.ext', 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:attacker.example\n')
sh(`openssl x509 -req -in att.csr -CA root.crt -CAkey root.key -CAcreateserial -out att.crt -days 2 -extfile att.ext`)
eckey('forged.key')
sh(`openssl req -new -key forged.key -out forged.csr -subj "/CN=victim.example"`)
writeExt('forged.ext', 'subjectAltName=DNS:victim.example\n')
sh(`openssl x509 -req -in forged.csr -CA att.crt -CAkey att.key -CAcreateserial -out forged.crt -days 2 -extfile forged.ext`)

// Inject our test root into the (process-local) trust store cache.
const roots = trustedRoots()
const restoreLen = roots.length
roots.push(new crypto.X509Certificate(fs.readFileSync(path.join(D, 'root.crt'))))
after(() => { roots.length = restoreLen; fs.rmSync(D, { recursive: true, force: true }) })

test('valid chain (leaf <- intermediate CA <- root) is accepted', () => {
	const r = validateChain([der('good.crt'), der('int.crt'), der('root.crt')], 'good.example')
	assert.strictEqual(r.ok, true, r.reason)
})

test('forged cert signed by a non-CA leaf is REJECTED (CA:TRUE constraint)', () => {
	const r = validateChain([der('forged.crt'), der('att.crt'), der('root.crt')], 'victim.example')
	assert.strictEqual(r.ok, false)
	assert.match(r.reason, /not a CA/)
})

test('CertificateVerify: valid ECDSA signature accepted; tamper/wrong-hash/wrong-scheme rejected', () => {
	const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(D, 'good.crt')))
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'good.key')))
	const transcriptHash = crypto.createHash('sha256').update('transcript').digest()
	const content = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0]), transcriptHash])
	const sig = crypto.sign('sha256', content, priv)
	assert.strictEqual(verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash }), true)
	const bad = Buffer.from(sig); bad[bad.length - 1] ^= 0x01
	assert.strictEqual(verifyCertVerify({ scheme: 0x0403, signature: bad, leaf, transcriptHash }), false, 'tampered sig')
	assert.strictEqual(verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash: crypto.randomBytes(32) }), false, 'wrong transcript')
	assert.strictEqual(verifyCertVerify({ scheme: 0x0804, signature: sig, leaf, transcriptHash }), false, 'rsa scheme for ec key')
	assert.strictEqual(verifyCertVerify({ scheme: 0xffff, signature: sig, leaf, transcriptHash }), false, 'unknown scheme')
})

test('CertificateVerify: valid RSA-PSS (rsa_pss_rsae_sha384) signature accepted', () => {
	sh(`openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 2 -subj "/CN=rsa.example"`)
	const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(D, 'rsa.crt')))
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'rsa.key')))
	const transcriptHash = crypto.createHash('sha384').update('x').digest()
	const content = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0]), transcriptHash])
	const sig = crypto.sign('sha384', content, { key: priv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST })
	assert.strictEqual(verifyCertVerify({ scheme: 0x0805, signature: sig, leaf, transcriptHash }), true)
})

test('parseCertificateList round-trips a Certificate message (plain + brotli)', () => {
	const leafDer = der('good.crt')
	const entry = Buffer.concat([u24(leafDer.length), leafDer, Buffer.from([0, 0])])  // cert + empty exts
	const body = Buffer.concat([Buffer.from([0]), u24(entry.length), entry])          // empty ctx + list
	const certs = parseCertificateList(body)
	assert.strictEqual(certs.length, 1)
	assert.ok(certs[0].equals(leafDer))
	const viaBrotli = parseCertificateList(zlib.brotliDecompressSync(zlib.brotliCompressSync(body)))
	assert.ok(viaBrotli[0].equals(leafDer))
})

test('parseCertificateList rejects truncated input instead of silently mis-parsing', () => {
	assert.throws(() => parseCertificateList(Buffer.from([0x00, 0x00, 0x00, 0x10])))  // claims 16-byte list, none present
})
