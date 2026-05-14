// RFC 6265 cookie jar tests.

const test = require('node:test')
const assert = require('node:assert')
const { Jar, parseSetCookie, domainMatch, pathMatch } = require('../../lib/cookies')

test('parseSetCookie: name/value + attributes', () => {
	const r = parseSetCookie('SID=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600')
	assert.strictEqual(r.name, 'SID')
	assert.strictEqual(r.value, 'abc')
	assert.strictEqual(r.attrs.domain, 'example.com')
	assert.strictEqual(r.attrs.path, '/')
	assert.strictEqual(r.attrs.secure, '')
	assert.strictEqual(r.attrs.httponly, '')
	assert.strictEqual(r.attrs.samesite, 'Lax')
	assert.strictEqual(r.attrs['max-age'], '3600')
})

test('domainMatch: exact + dotted-suffix + IP rejection', () => {
	assert.strictEqual(domainMatch('example.com', 'example.com'), true)
	assert.strictEqual(domainMatch('example.com', 'sub.example.com'), true)
	assert.strictEqual(domainMatch('example.com', 'evil.com'), false)
	assert.strictEqual(domainMatch('example.com', 'badexample.com'), false)
	assert.strictEqual(domainMatch('1.2.3.4', '1.2.3.4'), true)
	assert.strictEqual(domainMatch('1.2.3', '1.1.2.3'), false)   // IP host can't match a "domain"
})

test('pathMatch: RFC 6265 rules', () => {
	assert.strictEqual(pathMatch('/', '/'), true)
	assert.strictEqual(pathMatch('/', '/foo'), true)
	assert.strictEqual(pathMatch('/foo', '/foo'), true)
	assert.strictEqual(pathMatch('/foo', '/foo/bar'), true)
	assert.strictEqual(pathMatch('/foo', '/foobar'), false)
	assert.strictEqual(pathMatch('/foo/', '/foo/bar'), true)
})

test('Jar: setCookie + getCookieString round-trip', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/'), 'SID=abc')
})

test('Jar: Secure cookies blocked on http', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/; Secure', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/'), 'SID=abc')
	assert.strictEqual(j.getCookieString('http://example.com/'), '')
})

test('Jar: Max-Age=0 deletes the cookie', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/'), 'SID=abc')
	j.setCookie('SID=abc; Path=/; Max-Age=0', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/'), '')
})

test('Jar: Domain attribute applies to subdomains', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Domain=example.com', 'https://api.example.com/')
	assert.strictEqual(j.getCookieString('https://www.example.com/'), 'SID=abc')
	assert.strictEqual(j.getCookieString('https://example.com/'), 'SID=abc')
	assert.strictEqual(j.getCookieString('https://example.org/'), '')
})

test('Jar: hostOnly cookie does NOT cross subdomains', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://api.example.com/')
	assert.strictEqual(j.getCookieString('https://api.example.com/'), 'SID=abc')
	assert.strictEqual(j.getCookieString('https://www.example.com/'), '')
})

test('Jar: Domain MUST domain-match the request host (cross-site rejection)', () => {
	const j = new Jar()
	// Setting a cookie for evil.com from example.com is rejected.
	j.setCookie('SID=evil; Domain=evil.com', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://evil.com/'), '')
})

test('Jar: Path defaulting follows RFC 6265 §5.1.4', () => {
	const j = new Jar()
	j.setCookie('A=1', 'https://example.com/foo/bar')
	// Default-path = '/foo'. Cookie should appear on /foo and /foo/anything, not /.
	assert.strictEqual(j.getCookieString('https://example.com/foo/'), 'A=1')
	assert.strictEqual(j.getCookieString('https://example.com/foo/x'), 'A=1')
	assert.strictEqual(j.getCookieString('https://example.com/bar'), '')
})

test('Jar: Path attribute when set is honored', () => {
	const j = new Jar()
	j.setCookie('A=1; Path=/admin', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/admin'), 'A=1')
	assert.strictEqual(j.getCookieString('https://example.com/'), '')
})

test('Jar: longer path is sent first (RFC 6265 §5.4)', () => {
	const j = new Jar()
	j.setCookie('A=root; Path=/', 'https://example.com/')
	j.setCookie('B=deep; Path=/api', 'https://example.com/')
	const s = j.getCookieString('https://example.com/api/x')
	assert.match(s, /^B=deep; A=root$/)
})

test('Jar: expired Expires drops cookie', () => {
	const j = new Jar()
	j.setCookie('A=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'https://example.com/')
	assert.strictEqual(j.getCookieString('https://example.com/'), '')
})

test('Jar: public suffix list blocks Domain=co.uk', () => {
	const j = new Jar()
	j.setPublicSuffixList(new Set(['co.uk']))
	j.setCookie('SID=evil; Domain=co.uk', 'https://example.co.uk/')
	assert.strictEqual(j.getCookieString('https://example.co.uk/'), '')
})

test('Jar: gc() removes expired cookies', () => {
	const j = new Jar()
	j.setCookie('A=1; Max-Age=1', 'https://example.com/')
	assert.strictEqual(j.cookies.length, 1)
	// Force-expire
	j.cookies[0].expiresAt = Date.now() - 1
	j.gc()
	assert.strictEqual(j.cookies.length, 0)
})
