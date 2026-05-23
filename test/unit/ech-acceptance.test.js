const crypto = require('crypto')
const test = require('node:test')
const assert = require('node:assert')
const { EventEmitter } = require('node:events')


const {
	CreateSNIExtension,
	CreateSupportedVersionsExtension,
} = require('../../lib/extensions')
const {
	buildECHOffer,
	computeECHAcceptanceConfirmation,
	confirmECHAcceptance,
} = require('../../lib/tls/ech-clienthello')

const HRR_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex')

function makeOffer() {
	return buildECHOffer({
		config: {
			configId: 7,
			maximumNameLength: 18,
			raw: Buffer.from('fe0d000401020304', 'hex'),
		},
		innerHello: {
			legacyVersion: Buffer.from([0x03, 0x03]),
			random: Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'),
			sessionId: Buffer.from('11223344', 'hex'),
			cipherSuites: Buffer.from('1301', 'hex'),
			compressionMethods: Buffer.from([0x01, 0x00]),
		},
		outerHello: {
			legacyVersion: Buffer.from([0x03, 0x03]),
			random: Buffer.from('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100', 'hex'),
			sessionId: Buffer.from('11223344', 'hex'),
			cipherSuites: Buffer.from('1301', 'hex'),
			compressionMethods: Buffer.from([0x01, 0x00]),
		},
		innerExtensions: [
			CreateSNIExtension('secret.example'),
			CreateSupportedVersionsExtension(0x0a, [0x0304], { useGrease: false }),
		],
		outerExtensions: [
			CreateSNIExtension('public.example'),
			CreateSupportedVersionsExtension(0x0a, [0x0304, 0x0303], { useGrease: false }),
		],
		echExtensionIndex: 1,
		compressExtensionTypes: [],
		sender: {
			kdfId: 0x0001,
			aeadId: 0x0001,
			enc: Buffer.from('01020304', 'hex'),
			async seal(plaintext) {
				return Buffer.concat([Buffer.alloc(plaintext.length, 0x44), Buffer.alloc(16, 0x55)])
			},
		},
	})
}

function makeServerHello(random, extensions = Buffer.alloc(0), cipherSuite = 0x1301) {
	const extLen = Buffer.alloc(2)
	extLen.writeUInt16BE(extensions.length, 0)
	const body = Buffer.concat([
		Buffer.from([0x03, 0x03]),
		random,
		Buffer.from([0x00]),
		Buffer.from([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]),
		Buffer.from([0x00]),
		extLen,
		extensions,
	])
	const len = Buffer.alloc(3)
	len.writeUIntBE(body.length, 0, 3)
	return Buffer.concat([Buffer.from([0x02]), len, body])
}

function makeExtension(type, data) {
	const ext = Buffer.alloc(4)
	ext.writeUInt16BE(type, 0)
	ext.writeUInt16BE(data.length, 2)
	return Buffer.concat([ext, data])
}

function u8(value) {
	return Buffer.from([value])
}

function u16(value) {
	const buf = Buffer.alloc(2)
	buf.writeUInt16BE(value, 0)
	return buf
}

function opaque8(buf) {
	return Buffer.concat([u8(buf.length), buf])
}

function opaque16(buf) {
	return Buffer.concat([u16(buf.length), buf])
}

function buildRetryConfigList(configId) {
	const contents = Buffer.concat([
		u8(configId),
		u16(0x0020),
		opaque16(Buffer.from('aabbccdd', 'hex')),
		opaque16(Buffer.concat([u16(0x0001), u16(0x0001)])),
		u8(18),
		opaque8(Buffer.from('public.example', 'ascii')),
		opaque16(Buffer.alloc(0)),
	])
	const config = Buffer.concat([u16(0xfe0d), opaque16(contents)])
	return Buffer.concat([u16(config.length), config])
}

function makeHttp1Connection(responseText) {
	class FakeTransport extends EventEmitter {
		write() {
			queueMicrotask(() => {
				this.emit('data', Buffer.from(responseText, 'latin1'))
				this.emit('end')
			})
		}
	}
	return {
		alpn: 'http/1.1',
		h2Transport: new FakeTransport(),
		h1InFlight: false,
		activeRequests: 0,
		markUsed() {},
		scheduleIdleClose() {},
		canIssueRequest() { return true },
		close() {},
	}
}


test('confirmECHAcceptance matches ServerHello random confirmation', async () => {
	const offer = await makeOffer()
	const random = Buffer.from('1234567890abcdef1234567890abcdef1234567890abcdef0000000000000000', 'hex')
	const modifiedServerHello = makeServerHello(random)
	const transcriptHash = crypto.createHash('sha256')
		.update(offer.innerClientHelloHandshake)
		.update(modifiedServerHello)
		.digest()
	const confirmation = computeECHAcceptanceConfirmation({
		clientHelloInnerRandom: offer.innerRandom,
		transcriptHash,
		hashName: 'sha256',
	})
	confirmation.copy(random, 24)
	const acceptedServerHello = makeServerHello(random)
	assert.strictEqual(confirmECHAcceptance({
		clientHelloInner: offer.innerClientHelloHandshake,
		serverHello: acceptedServerHello,
		hashName: 'sha256',
	}), true)
	random.fill(0xaa, 24)
	assert.strictEqual(confirmECHAcceptance({
		clientHelloInner: offer.innerClientHelloHandshake,
		serverHello: makeServerHello(random),
		hashName: 'sha256',
	}), false)
})

test('confirmECHAcceptance matches HelloRetryRequest confirmation extension', async () => {
	const offer = await makeOffer()
	const echExtension = makeExtension(0xfe0d, Buffer.alloc(8))
	const supportedVersions = makeExtension(0x002b, Buffer.from([0x03, 0x04]))
	const modifiedHrr = makeServerHello(HRR_RANDOM, Buffer.concat([supportedVersions, echExtension]))
	const transcriptHash = crypto.createHash('sha256')
		.update(offer.innerClientHelloHandshake)
		.update(modifiedHrr)
		.digest()
	const confirmation = computeECHAcceptanceConfirmation({
		clientHelloInnerRandom: offer.innerRandom,
		transcriptHash,
		hashName: 'sha256',
		helloRetryRequest: true,
	})
	const acceptedHrr = makeServerHello(HRR_RANDOM, Buffer.concat([
		supportedVersions,
		makeExtension(0xfe0d, confirmation),
	]))
	assert.strictEqual(confirmECHAcceptance({
		clientHelloInner: offer.innerClientHelloHandshake,
		serverHello: acceptedHrr,
		hashName: 'sha256',
		helloRetryRequest: true,
	}), true)
	assert.throws(() => confirmECHAcceptance({
		clientHelloInner: offer.innerClientHelloHandshake,
		serverHello: makeServerHello(HRR_RANDOM, makeExtension(0xfe0d, Buffer.alloc(7))),
		hashName: 'sha256',
		helloRetryRequest: true,
	}), /invalid ECH HelloRetryRequest confirmation length/)
})

test('request retries once with retry_configs on a fresh TCP transport', async () => {
	const dnsModule = require('../../lib/dns/https-records')
	const originalResolveHttpsRecords = dnsModule.resolveHttpsRecords
	const clientPath = require.resolve('../../lib/client')
	const initialConfigs = buildRetryConfigList(1)
	const retryConfigs = buildRetryConfigList(7)
	const calls = []

	dnsModule.resolveHttpsRecords = async () => ({
		connectName: 'backend.example',
		port: 8443,
		ipv4hint: ['192.0.2.10'],
		ipv6hint: ['2001:db8::10'],
		echConfigList: initialConfigs,
	})
	delete require.cache[clientPath]
	const request = require('../../lib/client')
	const originalAcquire = request.pool.acquire
	request.pool.acquire = async (args) => {
		calls.push(args)
		if (calls.length === 1) {
			const err = new Error('ECH rejected')
			err.code = 'EECHREJECT'
			err.retryConfigs = retryConfigs
			throw err
		}
		return makeHttp1Connection('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
	}

	try {
		const body = await request({ url: 'https://secret.example/', ech: true, verifyTLS: false })
		assert.strictEqual(body, 'ok')
		assert.strictEqual(calls.length, 2)
		assert.strictEqual(calls[0].host, 'secret.example')
		assert.strictEqual(calls[0].connectHost, 'backend.example')
		assert.strictEqual(calls[0].port, 8443)
		assert.deepStrictEqual(calls[0].addressHints, { v4: ['192.0.2.10'], v6: ['2001:db8::10'] })
		assert.strictEqual(calls[0].ech.config.configId, 1)
		assert.strictEqual(calls[0].forceFresh, false)
		assert.strictEqual(calls[1].forceFresh, true)
		assert.strictEqual(calls[1].cacheConnection, true)
		assert.strictEqual(calls[1].ech.config.configId, 7)
	} finally {
		request.pool.acquire = originalAcquire
		dnsModule.resolveHttpsRecords = originalResolveHttpsRecords
		delete require.cache[clientPath]
	}
})

test('opportunistic h3 falls back to TCP for ECH requests when UDP fails', async () => {
	const dnsModule = require('../../lib/dns/https-records')
	const poolModule = require('../../lib/pool')
	const originalResolveHttpsRecords = dnsModule.resolveHttpsRecords
	const clientPath = require.resolve('../../lib/client')
	const initialConfigs = buildRetryConfigList(1)
	const calls = []

	dnsModule.resolveHttpsRecords = async () => ({
		connectName: 'backend.example',
		port: 8443,
		alpn: ['h2', 'h3'],
		ipv4hint: ['192.0.2.10'],
		echConfigList: initialConfigs,
	})
	poolModule.recordAltSvc('secret.example', 'h3=":443"; ma=60')
	delete require.cache[clientPath]
	const request = require('../../lib/client')
	const originalAcquire = request.pool.acquire
	request.pool.acquire = async (args) => {
		calls.push(args)
		if (args.transport === 'quic') {
			const err = new Error('udp down')
			err.code = 'EHOSTUNREACH'
			throw err
		}
		return makeHttp1Connection('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
	}

	try {
		const body = await request({ url: 'https://secret.example/', ech: true, verifyTLS: false })
		assert.strictEqual(body, 'ok')
		assert.strictEqual(calls.length, 2)
		assert.strictEqual(calls[0].transport, 'quic')
		assert.strictEqual(calls[0].ech.config.configId, 1)
		assert.strictEqual(calls[1].transport, 'tcp')
		assert.strictEqual(calls[1].port, 8443)
		assert.strictEqual(calls[1].ech.config.configId, 1)
	} finally {
		request.pool.acquire = originalAcquire
		poolModule.clearAltSvc()
		dnsModule.resolveHttpsRecords = originalResolveHttpsRecords
		delete require.cache[clientPath]
	}
})

const { QuicConnection } = require('../../lib/h3/connection')

test('QuicConnection prefers IPv4 hints when both address families are available', () => {
	const conn = new QuicConnection('secret.example', 443, {
		addressHints: {
			v6: ['2001:db8::10'],
			v4: ['192.0.2.10'],
		},
	})
	assert.deepStrictEqual(conn._resolveServerAddr(), {
		host: '192.0.2.10',
		port: 443,
		family: 'udp4',
	})
})

test('successful retry_configs replacement is reused by later requests for the same origin', async () => {
	const dnsModule = require('../../lib/dns/https-records')
	const originalResolveHttpsRecords = dnsModule.resolveHttpsRecords
	const clientPath = require.resolve('../../lib/client')
	const initialConfigs = buildRetryConfigList(1)
	const retryConfigs = buildRetryConfigList(7)
	const calls = []

	dnsModule.resolveHttpsRecords = async () => ({
		connectName: 'backend.example',
		port: 8443,
		ipv4hint: ['192.0.2.10'],
		echConfigList: initialConfigs,
	})
	delete require.cache[clientPath]
	const request = require('../../lib/client')
	const originalAcquire = request.pool.acquire
	request.pool.acquire = async (args) => {
		calls.push(args)
		if (calls.length === 1) {
			const err = new Error('ECH rejected')
			err.code = 'EECHREJECT'
			err.retryConfigs = retryConfigs
			throw err
		}
		return makeHttp1Connection('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
	}

	try {
		assert.strictEqual(await request({ url: 'https://secret.example/', ech: true, verifyTLS: false }), 'ok')
		request.pool.closeAll()
		request.pool.connections.clear()
		assert.strictEqual(await request({ url: 'https://secret.example/', ech: true, verifyTLS: false, forever: false }), 'ok')
		assert.strictEqual(calls.length, 3)
		assert.strictEqual(calls[1].ech.config.configId, 7)
		assert.strictEqual(calls[2].ech.config.configId, 7)
	} finally {
		request.pool.acquire = originalAcquire
		dnsModule.resolveHttpsRecords = originalResolveHttpsRecords
		delete require.cache[clientPath]
	}
})

test('same-origin redirects stop forcing fresh handshakes after a successful ECH retry', async () => {
	const dnsModule = require('../../lib/dns/https-records')
	const originalResolveHttpsRecords = dnsModule.resolveHttpsRecords
	const clientPath = require.resolve('../../lib/client')
	const initialConfigs = buildRetryConfigList(1)
	const retryConfigs = buildRetryConfigList(7)
	const calls = []

	dnsModule.resolveHttpsRecords = async () => ({
		connectName: 'backend.example',
		port: 8443,
		ipv4hint: ['192.0.2.10'],
		echConfigList: initialConfigs,
	})
	delete require.cache[clientPath]
	const request = require('../../lib/client')
	const originalAcquire = request.pool.acquire
	request.pool.acquire = async (args) => {
		calls.push(args)
		if (calls.length === 1) {
			const err = new Error('ECH rejected')
			err.code = 'EECHREJECT'
			err.retryConfigs = retryConfigs
			throw err
		}
		if (calls.length === 2) {
			return makeHttp1Connection('HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n')
		}
		return makeHttp1Connection('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
	}

	try {
		assert.strictEqual(await request({ url: 'https://secret.example/start', ech: true, verifyTLS: false }), 'ok')
		assert.strictEqual(calls.length, 3)
		assert.strictEqual(calls[1].forceFresh, true)
		assert.strictEqual(calls[2].forceFresh, false)
		assert.strictEqual(calls[2].ech.config.configId, 7)
	} finally {
		request.pool.acquire = originalAcquire
		dnsModule.resolveHttpsRecords = originalResolveHttpsRecords
		delete require.cache[clientPath]
	}
})

test('callback form receives both response and body', async () => {
	const clientPath = require.resolve('../../lib/client')
	delete require.cache[clientPath]
	const request = require('../../lib/client')
	const originalAcquire = request.pool.acquire
	request.pool.acquire = async () => makeHttp1Connection('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

	try {
		const promise = new Promise((resolve, reject) => {
			const returnPromise = request({ url: 'https://secret.example/', verifyTLS: false }, (err, res, cbBody) => {
				try {
					assert.ifError(err)
					assert.ok(res)
					assert.strictEqual(res.statusCode, 200)
					assert.strictEqual(cbBody, 'ok')
					resolve(returnPromise)
				} catch (e) {
					reject(e)
				}
			})
		})
		assert.strictEqual(await promise, 'ok')
	} finally {
		request.pool.acquire = originalAcquire
		delete require.cache[clientPath]
	}
})
