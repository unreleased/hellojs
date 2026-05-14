// Certificate chain validation — accept/reject paths.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const { execSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { validateChain, hostnameMatches, trustedRoots } = require('../../lib/tls/cert-validate')

function genSelfSigned(cn, san = `DNS:${cn}`, validity = 1) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcert-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days ${validity} -subj "/CN=${cn}" -addext "subjectAltName=${san}" 2>/dev/null`)
	const certPem = fs.readFileSync(c)
	const der = new crypto.X509Certificate(certPem).raw
	fs.rmSync(dir, { recursive: true, force: true })
	return Buffer.from(der)
}

function genCertPem(cn, san) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcert-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=${cn}" -addext "subjectAltName=${san}" 2>/dev/null`)
	const pem = fs.readFileSync(c, 'utf8')
	fs.rmSync(dir, { recursive: true, force: true })
	return pem
}

test('hostnameMatches: exact match', () => {
	const cert = new crypto.X509Certificate(genCertPem('example.com', 'DNS:example.com,DNS:*.example.com'))
	assert.strictEqual(hostnameMatches(cert, 'example.com'), true)
})

test('hostnameMatches: wildcard match', () => {
	const cert = new crypto.X509Certificate(genCertPem('test', 'DNS:*.example.com'))
	assert.strictEqual(hostnameMatches(cert, 'foo.example.com'), true, 'one-level wildcard match')
	assert.strictEqual(hostnameMatches(cert, 'example.com'), false, 'wildcard does not match parent')
	assert.strictEqual(hostnameMatches(cert, 'foo.bar.example.com'), false, 'wildcard does not match nested')
})

test('hostnameMatches: case-insensitive', () => {
	const cert = new crypto.X509Certificate(genCertPem('test', 'DNS:Example.COM'))
	assert.strictEqual(hostnameMatches(cert, 'example.com'), true)
	assert.strictEqual(hostnameMatches(cert, 'EXAMPLE.COM'), true)
})

test('validateChain rejects self-signed not in trust store', () => {
	const der = genSelfSigned('localhost')
	const r = validateChain([der], 'localhost')
	assert.strictEqual(r.ok, false)
	assert.match(r.reason, /chain does not terminate in a trusted root/)
})

test('validateChain rejects hostname mismatch', () => {
	const der = genSelfSigned('legit.com')
	const r = validateChain([der], 'evil.com')
	assert.strictEqual(r.ok, false)
	assert.match(r.reason, /does not match hostname/)
})

test('validateChain rejects expired cert (notAfter in past)', () => {
	// Generate a cert valid for 1 day, then evaluate it 2 days from "now".
	const der = genSelfSigned('localhost')
	const future = Date.now() + 2 * 24 * 60 * 60 * 1000
	const r = validateChain([der], 'localhost', { now: future })
	assert.strictEqual(r.ok, false)
	assert.match(r.reason, /expired/)
})

test('validateChain rejects empty chain', () => {
	const r = validateChain([], 'example.com')
	assert.strictEqual(r.ok, false)
})

test('trustedRoots populates from Node bundled CAs (non-zero)', () => {
	const roots = trustedRoots()
	assert.strictEqual(roots.length > 50, true, `expected > 50 bundled roots, got ${roots.length}`)
})
