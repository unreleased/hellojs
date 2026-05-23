const dgram = require('node:dgram')
const dns = require('node:dns')
const net = require('node:net')
const test = require('node:test')
const assert = require('node:assert')
const { parseHttpsResponse, chooseHttpsEndpoint, resolveHttpsRecords } = require('../../lib/dns/https-records')
const { buildQuery, parseResponse, sendDnsQuery } = require('../../lib/dns/wire')
const { resolveBoth } = require('../../lib/happy-eyeballs')

const TYPE_SVCB = 64
const TYPE_HTTPS = 65
const CLASS_IN = 1

function encodeName(name) {
	if (!name || name === '.') return Buffer.from([0])
	const normalized = name.endsWith('.') ? name.slice(0, -1) : name
	if (!normalized) return Buffer.from([0])
	const parts = []
	for (const label of normalized.split('.')) {
		const buf = Buffer.from(label, 'utf8')
		parts.push(Buffer.from([buf.length]), buf)
	}
	parts.push(Buffer.from([0]))
	return Buffer.concat(parts)
}

function encodeParam(key, value) {
	const header = Buffer.alloc(4)
	header.writeUInt16BE(key, 0)
	header.writeUInt16BE(value.length, 2)
	return Buffer.concat([header, value])
}

function encodeMandatory(keys) {
	const buf = Buffer.alloc(keys.length * 2)
	let offset = 0
	for (const key of keys) {
		buf.writeUInt16BE(key, offset)
		offset += 2
	}
	return buf
}

function encodeAlpn(values) {
	const parts = []
	for (const value of values) {
		const buf = Buffer.from(value, 'utf8')
		parts.push(Buffer.from([buf.length]), buf)
	}
	return Buffer.concat(parts)
}

function encodePort(port) {
	const buf = Buffer.alloc(2)
	buf.writeUInt16BE(port, 0)
	return buf
}

function encodeIpv4(addresses) {
	const bytes = []
	for (const address of addresses) {
		for (const part of address.split('.')) bytes.push(Number(part))
	}
	return Buffer.from(bytes)
}

function encodeIpv6(addresses) {
	const parts = []
	for (const address of addresses) {
		const groups = address.split(':')
		const buf = Buffer.alloc(16)
		for (let i = 0; i < groups.length; i++) {
			buf.writeUInt16BE(parseInt(groups[i], 16), i * 2)
		}
		parts.push(buf)
	}
	return Buffer.concat(parts)
}

function buildHttpsResponse(name, records, type = TYPE_HTTPS) {
	const question = Buffer.concat([
		encodeName(name),
		Buffer.from([0, type, 0, CLASS_IN]),
	])
	const answers = records.map((record) => {
		const params = []
		if (record.params?.mandatory) params.push(encodeParam(0, encodeMandatory(record.params.mandatory)))
		if (record.params?.alpn) params.push(encodeParam(1, encodeAlpn(record.params.alpn)))
		if ('noDefaultAlpn' in (record.params || {})) params.push(encodeParam(2, Buffer.alloc(0)))
		if (record.params?.port) params.push(encodeParam(3, encodePort(record.params.port)))
		if (record.params?.ipv4hint) params.push(encodeParam(4, encodeIpv4(record.params.ipv4hint)))
		if (record.params?.echConfigList) params.push(encodeParam(5, record.params.echConfigList))
		if (record.params?.ipv6hint) params.push(encodeParam(6, encodeIpv6(record.params.ipv6hint)))
		const rdata = Buffer.concat([
			encodePort(record.priority),
			encodeName(record.targetName),
			...params,
		])
		const header = Buffer.alloc(10)
		header.writeUInt16BE(record.type || type, 0)
		header.writeUInt16BE(CLASS_IN, 2)
		header.writeUInt32BE(60, 4)
		header.writeUInt16BE(rdata.length, 8)
		return Buffer.concat([encodeName(record.name || name), header, rdata])
	})
	const dnsHeader = Buffer.alloc(12)
	dnsHeader.writeUInt16BE(0x1234, 0)
	dnsHeader.writeUInt16BE(0x8180, 2)
	dnsHeader.writeUInt16BE(1, 4)
	dnsHeader.writeUInt16BE(answers.length, 6)
	return Buffer.concat([dnsHeader, question, ...answers])
}

test('parses HTTPS RR with ech, alpn, port, and address hints', () => {
	const rrset = parseHttpsResponse(buildHttpsResponse('svc.example', [
		{
			priority: 1,
			targetName: 'backend.example',
			params: {
				mandatory: [1, 3, 5],
				alpn: ['h2', 'h3'],
				port: 8443,
				ipv4hint: ['192.0.2.10', '192.0.2.11'],
				ipv6hint: ['2001:db8:0:0:0:0:0:10'],
				echConfigList: Buffer.from('0010deadbeef', 'hex'),
			},
		},
	]))

	assert.deepStrictEqual(rrset.aliasMode, [])
	assert.strictEqual(rrset.serviceMode.length, 1)
	assert.deepStrictEqual(rrset.serviceMode[0].params.alpn, ['h2', 'h3'])
	assert.strictEqual(rrset.serviceMode[0].params.port, 8443)
	assert.deepStrictEqual(rrset.serviceMode[0].params.ipv4hint, ['192.0.2.10', '192.0.2.11'])
	assert.deepStrictEqual(rrset.serviceMode[0].params.ipv6hint, ['2001:db8:0:0:0:0:0:10'])
	assert.deepStrictEqual(rrset.serviceMode[0].params.mandatory, ['alpn', 'port', 'echConfigList'])
	assert.deepStrictEqual(rrset.serviceMode[0].params.echConfigList, Buffer.from('0010deadbeef', 'hex'))
})

test('parses HTTPS RR with no-default-alpn metadata', () => {
	const rrset = parseHttpsResponse(buildHttpsResponse('svc.example', [
		{
			priority: 1,
			targetName: 'backend.example',
			params: {
				mandatory: [2],
				noDefaultAlpn: true,
				echConfigList: Buffer.from('0011', 'hex'),
			},
		},
	]))

	assert.strictEqual(rrset.serviceMode[0].params.noDefaultAlpn, true)
	assert.deepStrictEqual(rrset.serviceMode[0].params.mandatory, ['noDefaultAlpn'])
})

test('parseHttpsResponse rejects non-empty no-default-alpn values', () => {
	const response = buildHttpsResponse('svc.example', [
		{
			priority: 1,
			targetName: 'backend.example',
			params: {
				noDefaultAlpn: true,
				echConfigList: Buffer.from('0012', 'hex'),
			},
		},
	])
	const start = response.lastIndexOf(Buffer.from([0x00, 0x02, 0x00, 0x00]))
	response.writeUInt16BE(1, start + 2)
	response[start + 4] = 0xff
	assert.throws(() => parseHttpsResponse(response), /invalid SvcParam noDefaultAlpn/)
})

test('parseHttpsResponse rejects mixed alias-mode and service-mode records for one owner', () => {
	assert.throws(() => parseHttpsResponse(buildHttpsResponse('svc.example', [
		{ priority: 0, targetName: 'alias.example', params: {} },
		{ priority: 1, targetName: 'backend.example', params: { echConfigList: Buffer.from('0013', 'hex') } },
	])) , /mixed alias and service mode records/)
})
test('parseHttpsResponse keeps only HTTPS answers for the queried owner name', () => {
	const rrset = parseHttpsResponse(buildHttpsResponse('svc.example', [
		{ priority: 0, targetName: 'alias.example', params: {} },
		{
			name: 'alias.example',
			priority: 1,
			targetName: 'backend.example',
			params: { alpn: ['h2'], echConfigList: Buffer.from('0050', 'hex') },
		},
	]))

	assert.strictEqual(rrset.aliasMode.length, 1)
	assert.strictEqual(rrset.aliasMode[0].targetName, 'alias.example')
	assert.deepStrictEqual(rrset.serviceMode, [])
})

test('parseHttpsResponse rejects non-zero DNS rcodes', () => {
	const response = buildHttpsResponse('svc.example', [])
	response.writeUInt16BE(0x8183, 2)
	assert.throws(() => parseHttpsResponse(response), /DNS lookup failed for svc\.example: NXDOMAIN/)
})

test('buildQuery encodes absolute owner names without an extra root label', () => {
	const message = parseResponse(buildQuery('svc.example.'))
	assert.strictEqual(message.questions.length, 1)
	assert.strictEqual(message.questions[0].name, 'svc.example')
	assert.strictEqual(message.questions[0].type, 'HTTPS')
})

test('parseHttpsResponse matches HTTPS owner names case-insensitively', () => {
	const rrset = parseHttpsResponse(buildHttpsResponse('Svc.Example', [
		{
			name: 'sVc.eXaMpLe',
			priority: 1,
			targetName: 'backend.example',
			params: { alpn: ['h2'], echConfigList: Buffer.from('0043', 'hex') },
		},
	]))

	assert.strictEqual(rrset.aliasMode.length, 0)
	assert.strictEqual(rrset.serviceMode.length, 1)
	assert.strictEqual(rrset.serviceMode[0].targetName, 'backend.example')
})

test('resolveHttpsRecords falls back to SVCB answers when HTTPS is empty', async () => {
	const responses = new Map([
		['svc.example:HTTPS', buildHttpsResponse('svc.example', [])],
		['svc.example:SVCB', buildHttpsResponse('svc.example', [
			{
				priority: 1,
				targetName: 'backend.example',
				params: {
					alpn: ['h2', 'h3'],
					port: 9443,
					echConfigList: Buffer.from('0044', 'hex'),
				},
			},
		], TYPE_SVCB)],
	])
	const seen = []

	const endpoint = await resolveHttpsRecords('svc.example', {
		resolver(query) {
			const message = parseResponse(query)
			const key = `${message.questions[0].name}:${message.questions[0].type}`
			seen.push(key)
			return Promise.resolve(responses.get(key))
		},
	})

	assert.deepStrictEqual(seen, ['svc.example:HTTPS', 'svc.example:SVCB'])
	assert.strictEqual(endpoint.ownerName, 'svc.example')
	assert.strictEqual(endpoint.connectName, 'backend.example')
	assert.strictEqual(endpoint.port, 9443)
	assert.deepStrictEqual(endpoint.alpn, ['h2', 'h3'])
	assert.deepStrictEqual(endpoint.echConfigList, Buffer.from('0044', 'hex'))
})

test('resolveHttpsRecords returns null when SVCB fallback is unsupported after an empty HTTPS RRset', async () => {
	const svcbFailure = buildHttpsResponse('svc.example', [], TYPE_SVCB)
	svcbFailure.writeUInt16BE(0x8184, 2)
	const responses = new Map([
		['svc.example:HTTPS', buildHttpsResponse('svc.example', [])],
		['svc.example:SVCB', svcbFailure],
	])
	const seen = []

	const endpoint = await resolveHttpsRecords('svc.example', {
		resolver(query) {
			const message = parseResponse(query)
			const key = `${message.questions[0].name}:${message.questions[0].type}`
			seen.push(key)
			return Promise.resolve(responses.get(key))
		},
	})

	assert.strictEqual(endpoint, null)
	assert.deepStrictEqual(seen, ['svc.example:HTTPS', 'svc.example:SVCB'])
})

test('resolveHttpsRecords propagates SVCB fallback transport failures after an empty HTTPS RRset', async () => {
	const seen = []
	await assert.rejects(() => resolveHttpsRecords('svc.example', {
		resolver(query) {
			const message = parseResponse(query)
			const key = `${message.questions[0].name}:${message.questions[0].type}`
			seen.push(key)
			if (key === 'svc.example:HTTPS') return Promise.resolve(buildHttpsResponse('svc.example', []))
			return Promise.reject(new Error('DNS query timed out (svc.example:53)'))
		},
	}), /DNS query timed out/)
	assert.deepStrictEqual(seen, ['svc.example:HTTPS', 'svc.example:SVCB'])
})

test('resolveHttpsRecords does not fall back to SVCB on HTTPS lookup failure', async () => {
	const httpsFailure = buildHttpsResponse('svc.example', [])
	httpsFailure.writeUInt16BE(0x8182, 2)
	const responses = new Map([
		['svc.example:HTTPS', httpsFailure],
		['svc.example:SVCB', buildHttpsResponse('svc.example', [
			{
				priority: 1,
				targetName: 'backend.example',
				params: {
					alpn: ['h2'],
					echConfigList: Buffer.from('0045', 'hex'),
				},
			},
		], TYPE_SVCB)],
	])
	const seen = []

	await assert.rejects(() => resolveHttpsRecords('svc.example', {
		resolver(query) {
			const message = parseResponse(query)
			const key = `${message.questions[0].name}:${message.questions[0].type}`
			seen.push(key)
			return Promise.resolve(responses.get(key))
		},
	}), /DNS lookup failed for svc\.example: SERVFAIL/)
	assert.deepStrictEqual(seen, ['svc.example:HTTPS'])
})

test('sendDnsQuery rejects same-id responses for the wrong question', async () => {
	const originalCreateSocket = dgram.createSocket
	const response = buildHttpsResponse('other.example', [])
	dgram.createSocket = () => {
		const handlers = new Map()
		return {
			once(event, handler) {
				handlers.set(event, handler)
			},
			close() {},
			send(_message, _port, _host, callback) {
				callback(null)
				setImmediate(() => handlers.get('message')(Buffer.from(response)))
			},
		}
	}
	try {
		await assert.rejects(() => sendDnsQuery(buildQuery('svc.example', 'HTTPS', 0x1234)), /mismatched DNS response question/)
	} finally {
		dgram.createSocket = originalCreateSocket
	}
})


test('parseHttpsResponse rejects duplicate SvcParam keys', () => {
	const question = Buffer.concat([encodeName('svc.example'), Buffer.from([0x00, TYPE_HTTPS, 0x00, CLASS_IN])])
	const svcParams = Buffer.concat([
		encodeParam(5, Buffer.from('0014', 'hex')),
		encodeParam(5, Buffer.from('0015', 'hex')),
	])
	const rdata = Buffer.concat([
		Buffer.from([0x00, 0x01]),
		encodeName('backend.example'),
		svcParams,
	])
	const answerHeader = Buffer.alloc(10)
	answerHeader.writeUInt16BE(TYPE_HTTPS, 0)
	answerHeader.writeUInt16BE(CLASS_IN, 2)
	answerHeader.writeUInt32BE(60, 4)
	answerHeader.writeUInt16BE(rdata.length, 8)
	const dnsHeader = Buffer.alloc(12)
	dnsHeader.writeUInt16BE(0x1234, 0)
	dnsHeader.writeUInt16BE(0x8180, 2)
	dnsHeader.writeUInt16BE(1, 4)
	dnsHeader.writeUInt16BE(1, 6)
	const response = Buffer.concat([
		dnsHeader,
		question,
		encodeName('svc.example'),
		answerHeader,
		rdata,
	])
	assert.throws(() => parseHttpsResponse(response), /duplicate SvcParam echConfigList/)
})

test('sendDnsQuery uses host and port from dns.getServers entries', async () => {
	const originalGetServers = dns.getServers
	const originalCreateSocket = dgram.createSocket
	const seen = []
	dns.getServers = () => ['127.0.0.1:5300', '[2001:db8::53]:5400']
	dgram.createSocket = (family) => {
		const handlers = new Map()
		return {
			once(event, handler) {
				handlers.set(event, handler)
			},
			close() {},
			send(message, port, host, callback) {
				seen.push({ family, host, port, id: message.readUInt16BE(0) })
				callback(null)
				const response = Buffer.from(message)
				response.writeUInt16BE(response.readUInt16BE(2) | 0x8000, 2)
				setImmediate(() => handlers.get('message')(response))
			},
		}
	}
	try {
		await sendDnsQuery(buildQuery('svc.example'))
		await sendDnsQuery(buildQuery('svc.example'), { server: '[2001:db8::53]:5400' })
	} finally {
		dns.getServers = originalGetServers
		dgram.createSocket = originalCreateSocket
	}

	assert.deepStrictEqual(seen, [
		{ family: 'udp4', host: '127.0.0.1', port: 5300, id: seen[0].id },
		{ family: 'udp6', host: '2001:db8::53', port: 5400, id: seen[1].id },
	])
})


test('sendDnsQuery rejects same-id query echoes without QR set', async () => {
	const originalCreateSocket = dgram.createSocket
	dgram.createSocket = () => {
		const handlers = new Map()
		return {
			once(event, handler) {
				handlers.set(event, handler)
			},
			close() {},
			send(message, port, host, callback) {
				callback(null)
				setImmediate(() => handlers.get('message')(Buffer.from(message)))
			},
		}
	}
	try {
		await assert.rejects(() => sendDnsQuery(buildQuery('svc.example', 'HTTPS', 0x1234)), /invalid DNS response: QR bit not set/)
	} finally {
		dgram.createSocket = originalCreateSocket
	}
})
test('sendDnsQuery retries truncated UDP replies over TCP', async () => {
	const originalCreateSocket = dgram.createSocket
	const originalCreateConnection = net.createConnection
	const query = buildQuery('svc.example', 'HTTPS', 0x1234)
	const response = buildHttpsResponse('svc.example', [
		{ priority: 1, targetName: 'backend.example', params: { alpn: ['h2'], echConfigList: Buffer.from('0010', 'hex') } },
	])
	const truncated = Buffer.from(response)
	truncated.writeUInt16BE(truncated.readUInt16BE(2) | 0x0200, 2)
	const seen = { udp: 0, tcp: 0, tcpFrame: null }
	const tcpPayload = Buffer.alloc(response.length + 2)
	tcpPayload.writeUInt16BE(response.length, 0)
	response.copy(tcpPayload, 2)
	dgram.createSocket = () => {
		const handlers = new Map()
		return {
			once(event, handler) {
				handlers.set(event, handler)
			},
			close() {},
			send(message, port, host, callback) {
				seen.udp += 1
				callback(null)
				setImmediate(() => handlers.get('message')(Buffer.from(truncated)))
			},
		}
	}
	net.createConnection = (options) => {
		const handlers = new Map()
		setImmediate(() => handlers.get('connect')())
		return {
			once(event, handler) {
				handlers.set(event, handler)
			},
			on(event, handler) {
				handlers.set(event, handler)
			},
			end(payload) {
				seen.tcp += 1
				seen.tcpFrame = { options, payload: Buffer.from(payload) }
				setImmediate(() => handlers.get('data')(tcpPayload.subarray(0, 5)))
				setImmediate(() => handlers.get('data')(tcpPayload.subarray(5)))
			},
			destroy() {},
		}
	}
	try {
		const actual = await sendDnsQuery(query, { server: '127.0.0.1:53' })
		assert.deepStrictEqual(actual, response)
		assert.strictEqual(seen.udp, 1)
		assert.strictEqual(seen.tcp, 1)
		assert.deepStrictEqual(seen.tcpFrame, {
			options: { host: '127.0.0.1', port: 53, family: 4 },
			payload: Buffer.concat([Buffer.from([0x00, query.length]), query]),
		})
	} finally {
		dgram.createSocket = originalCreateSocket
		net.createConnection = originalCreateConnection
	}
})


test('chooses the lowest-priority usable HTTPS endpoint and detects svcb-reliant mode', () => {
	const endpoint = chooseHttpsEndpoint({
		serviceMode: [
			{ priority: 10, targetName: '.', params: { echConfigList: Buffer.from('0010', 'hex') } },
			{ priority: 1, targetName: 'alt.example', params: { mandatory: ['alpn', 'key65400'], alpn: ['h2'], echConfigList: Buffer.from('0020', 'hex') } },
			{ priority: 2, targetName: 'backend.example', params: { alpn: ['h2', 'h3'], port: 8443, ipv4hint: ['192.0.2.44'], echConfigList: Buffer.from('0030', 'hex') } },
		],
	})

	assert.strictEqual(endpoint.svcbReliant, true)
	assert.strictEqual(endpoint.targetName, 'backend.example')
	assert.strictEqual(endpoint.port, 8443)
	assert.deepStrictEqual(endpoint.alpn, ['h2', 'h3'])
	assert.deepStrictEqual(endpoint.ipv4hint, ['192.0.2.44'])
	assert.deepStrictEqual(endpoint.ipv6hint, [])
	assert.deepStrictEqual(endpoint.echConfigList, Buffer.from('0030', 'hex'))
	assert.strictEqual(endpoint.noDefaultAlpn, false)
})

test('chooses HTTPS endpoint with explicit no-default-alpn metadata', () => {
	const endpoint = chooseHttpsEndpoint({
		serviceMode: [
			{ priority: 1, targetName: 'backend.example', params: { mandatory: ['noDefaultAlpn'], noDefaultAlpn: true, echConfigList: Buffer.from('0031', 'hex') } },
		],
	})

	assert.deepStrictEqual(endpoint.alpn, [])
	assert.strictEqual(endpoint.noDefaultAlpn, true)
})

test('passes through to A/AAAA fallback when HTTPS resolution is absent', () => {
	assert.strictEqual(chooseHttpsEndpoint(null), null)
})

test('resolveHttpsRecords follows alias mode and returns connect metadata', async () => {
	const responses = new Map([
		['svc.example', buildHttpsResponse('svc.example', [
			{ priority: 0, targetName: 'alias.example', params: {} },
		])],
		['alias.example', buildHttpsResponse('alias.example', [
			{
				priority: 1,
				targetName: 'backend.example',
				params: {
					alpn: ['h2', 'h3'],
					port: 8443,
					ipv4hint: ['192.0.2.90'],
					echConfigList: Buffer.from('0040', 'hex'),
				},
			},
		])],
	])
	const seen = []

	const endpoint = await resolveHttpsRecords('svc.example.', {
		resolver(query) {
			const message = parseResponse(query)
			const name = message.questions[0].name
			seen.push(name)
			return Promise.resolve(responses.get(name))
		},
	})

	assert.deepStrictEqual(seen, ['svc.example', 'alias.example'])
	assert.strictEqual(endpoint.publicName, 'svc.example');
	assert.strictEqual(endpoint.ownerName, 'alias.example')
	assert.strictEqual(endpoint.connectName, 'backend.example')
	assert.strictEqual(endpoint.port, 8443)
	assert.deepStrictEqual(endpoint.alpn, ['h2', 'h3'])
	assert.deepStrictEqual(endpoint.ipv4hint, ['192.0.2.90'])
	assert.deepStrictEqual(endpoint.echConfigList, Buffer.from('0040', 'hex'))
})
test('resolveHttpsRecords ignores mixed-owner service records until the alias target is queried', async () => {
	const responses = new Map([
		['svc.example', buildHttpsResponse('svc.example', [
			{ priority: 0, targetName: 'alias.example', params: {} },
			{
				name: 'alias.example',
				priority: 1,
				targetName: 'wrong-if-mixed.example',
				params: { alpn: ['h3'], echConfigList: Buffer.from('0041', 'hex') },
			},
		])],
		['alias.example', buildHttpsResponse('alias.example', [
			{
				priority: 1,
				targetName: 'backend.example',
				params: {
					alpn: ['h2', 'h3'],
					ipv6hint: ['2001:db8:0:0:0:0:0:90'],
					echConfigList: Buffer.from('0042', 'hex'),
				},
			},
		])],
	])

	const endpoint = await resolveHttpsRecords('svc.example', {
		resolver(query) {
			const message = parseResponse(query)
			return Promise.resolve(responses.get(message.questions[0].name))
		},
	})

	assert.strictEqual(endpoint.ownerName, 'alias.example')
	assert.strictEqual(endpoint.connectName, 'backend.example')
	assert.deepStrictEqual(endpoint.alpn, ['h2', 'h3'])
	assert.deepStrictEqual(endpoint.ipv6hint, ['2001:db8:0:0:0:0:0:90'])
	assert.deepStrictEqual(endpoint.echConfigList, Buffer.from('0042', 'hex'))
})


test('resolveBoth prefers pre-resolved hints when provided', async () => {
	const hints = {
		v4: ['192.0.2.7'],
		v6: ['2001:db8:0:0:0:0:0:7'],
	}

	assert.deepStrictEqual(await resolveBoth('ignored.example', hints), hints)
})
test('resolveBoth falls back for the missing family when hints are partial', async () => {
	const resolve4 = require('node:dns').promises.resolve4
	const resolve6 = require('node:dns').promises.resolve6
	const calls = []
	require('node:dns').promises.resolve4 = async (host) => {
		calls.push(['v4', host])
		return ['192.0.2.8']
	}
	require('node:dns').promises.resolve6 = async (host) => {
		calls.push(['v6', host])
		return ['2001:db8:0:0:0:0:0:8']
	}
	try {
		assert.deepStrictEqual(
			await resolveBoth('svc.example', { v4: ['192.0.2.7'], v6: [] }),
			{ v4: ['192.0.2.7'], v6: ['2001:db8:0:0:0:0:0:8'] },
		)
		assert.deepStrictEqual(
			await resolveBoth('svc.example', { v4: [], v6: ['2001:db8:0:0:0:0:0:7'] }),
			{ v4: ['192.0.2.8'], v6: ['2001:db8:0:0:0:0:0:7'] },
		)
		assert.deepStrictEqual(calls, [
			['v6', 'svc.example'],
			['v4', 'svc.example'],
		])
	} finally {
		require('node:dns').promises.resolve4 = resolve4
		require('node:dns').promises.resolve6 = resolve6
	}
})
