// Minimal DNS wire codec for the HTTPS/SVCB bootstrap path.
//
// Scope is intentionally narrow:
//   - query construction for HTTPS/SVCB/A/AAAA
//   - response parsing for the same types
//   - enough name-compression support to read real recursive-resolver answers
//   - UDP first, with TCP retry when the TC bit is set
//
// This is not a general-purpose DNS library; it exists so ECH bootstrap can stay
// self-contained and avoid pulling in a large dependency just to decode HTTPS RRs.
const crypto = require('node:crypto')
const dgram = require('node:dgram')
const dns = require('node:dns')
const net = require('node:net')

const TYPE = {
	A: 1,
	AAAA: 28,
	SVCB: 64,
	HTTPS: 65,
}

const TYPE_NAMES = {
	1: 'A',
	28: 'AAAA',
	64: 'SVCB',
	65: 'HTTPS',
}

const SVC_PARAM_NAMES = {
	0: 'mandatory',
	1: 'alpn',
	2: 'noDefaultAlpn',
	3: 'port',
	4: 'ipv4hint',
	5: 'echConfigList',
	6: 'ipv6hint',
}
const DNS_FLAG_QR = 0x8000
const DNS_FLAG_TC = 0x0200
const DNS_RCODE_MASK = 0x000f

function buildQuery(name, type = 'HTTPS', id = crypto.randomInt(0x10000)) {
	const typeCode = typeof type === 'number' ? type : TYPE[type]
	if (!typeCode) throw new Error(`unsupported DNS type: ${type}`)
	const question = Buffer.concat([
		encodeName(name),
		u16(typeCode),
		u16(1),
	])
	const header = Buffer.alloc(12)
	header.writeUInt16BE(id, 0)
	header.writeUInt16BE(0x0100, 2)
	header.writeUInt16BE(1, 4)
	return Buffer.concat([header, question])
}

function parseResponse(buf) {
	if (buf.length < 12) throw new Error('truncated DNS message')
	let offset = 0
	const id = buf.readUInt16BE(offset); offset += 2
	const flags = buf.readUInt16BE(offset); offset += 2
	const qdcount = buf.readUInt16BE(offset); offset += 2
	const ancount = buf.readUInt16BE(offset); offset += 2
	const nscount = buf.readUInt16BE(offset); offset += 2
	const arcount = buf.readUInt16BE(offset); offset += 2
	const questions = []
	for (let i = 0; i < qdcount; i++) {
		const parsed = readName(buf, offset)
		offset = parsed.offset
		if (offset + 4 > buf.length) throw new Error('truncated DNS question')
		questions.push({
			name: parsed.name,
			type: TYPE_NAMES[buf.readUInt16BE(offset)] || buf.readUInt16BE(offset),
			class: buf.readUInt16BE(offset + 2),
		})
		offset += 4
	}
	const answers = []
	for (let i = 0; i < ancount; i++) {
		const parsed = parseRecord(buf, offset)
		offset = parsed.offset
		answers.push(parsed.record)
	}
	const authorities = []
	for (let i = 0; i < nscount; i++) {
		const parsed = parseRecord(buf, offset)
		offset = parsed.offset
		authorities.push(parsed.record)
	}
	const additionals = []
	for (let i = 0; i < arcount; i++) {
		const parsed = parseRecord(buf, offset)
		offset = parsed.offset
		additionals.push(parsed.record)
	}
	return {
		id,
		flags,
		isResponse: (flags & DNS_FLAG_QR) !== 0,
		rcode: flags & DNS_RCODE_MASK,
		questions,
		answers,
		authorities,
		additionals,
	}
}

function parseRecord(buf, offset) {
	const parsedName = readName(buf, offset)
	offset = parsedName.offset
	if (offset + 10 > buf.length) throw new Error('truncated DNS record header')
	const typeCode = buf.readUInt16BE(offset); offset += 2
	const rrclass = buf.readUInt16BE(offset); offset += 2
	const ttl = buf.readUInt32BE(offset); offset += 4
	const rdlength = buf.readUInt16BE(offset); offset += 2
	const end = offset + rdlength
	if (end > buf.length) throw new Error('truncated DNS record body')
	const record = {
		name: parsedName.name,
		type: TYPE_NAMES[typeCode] || typeCode,
		class: rrclass,
		ttl,
		rdata: buf.subarray(offset, end),
	}
	if (typeCode === TYPE.A) {
		record.address = formatIpv4(record.rdata)
	} else if (typeCode === TYPE.AAAA) {
		record.address = formatIpv6(record.rdata)
	} else if (typeCode === TYPE.SVCB || typeCode === TYPE.HTTPS) {
		const parsedHttps = parseHttpsRecord(buf, offset, end)
		record.priority = parsedHttps.priority
		record.targetName = parsedHttps.targetName
		record.params = parsedHttps.params
	}
	return { record, offset: end }
}

function parseHttpsRecord(buf, offset, end) {
	if (offset + 2 > end) throw new Error('truncated HTTPS priority')
	const priority = buf.readUInt16BE(offset)
	offset += 2
	const target = readName(buf, offset)
	offset = target.offset
	const params = parseSvcParams(buf, offset, end)
	return { priority, targetName: target.name, params }
}

function parseSvcParams(buf, offset, end) {
	const params = {}
	while (offset < end) {
		if (offset + 4 > end) throw new Error('truncated SvcParam header')
		const key = buf.readUInt16BE(offset); offset += 2
		const length = buf.readUInt16BE(offset); offset += 2
		const valueEnd = offset + length
		if (valueEnd > end) throw new Error('truncated SvcParam value')
		const value = buf.subarray(offset, valueEnd)
		offset = valueEnd
		const name = SVC_PARAM_NAMES[key] || `key${key}`
		if (Object.prototype.hasOwnProperty.call(params, name)) throw new Error(`duplicate SvcParam ${name}`)
		params[name] = parseSvcParamValue(key, value)
	}
	return params
}

function parseSvcParamValue(key, value) {
	switch (key) {
		case 0:
			return parseMandatory(value)
		case 1:
			return parseAlpn(value)
		case 2:
			if (value.length !== 0) throw new Error('invalid SvcParam noDefaultAlpn')
			return true
		case 3:
			if (value.length !== 2) throw new Error('invalid SvcParam port')
			return value.readUInt16BE(0)
		case 4:
			return parseAddressHints(value, 4, formatIpv4)
		case 5:
			return Buffer.from(value)
		case 6:
			return parseAddressHints(value, 16, formatIpv6)
		default:
			return Buffer.from(value)
	}
}

function parseMandatory(value) {
	if ((value.length % 2) !== 0) throw new Error('invalid mandatory SvcParam')
	const out = []
	for (let offset = 0; offset < value.length; offset += 2) {
		const key = value.readUInt16BE(offset)
		out.push(SVC_PARAM_NAMES[key] || `key${key}`)
	}
	return out
}

function parseAlpn(value) {
	const out = []
	for (let offset = 0; offset < value.length;) {
		const length = value[offset]
		offset += 1
		const end = offset + length
		if (end > value.length) throw new Error('invalid ALPN SvcParam')
		out.push(value.toString('utf8', offset, end))
		offset = end
	}
	return out
}

function parseAddressHints(value, size, formatter) {
	if ((value.length % size) !== 0) throw new Error('invalid address hint SvcParam')
	const out = []
	for (let offset = 0; offset < value.length; offset += size) {
		out.push(formatter(value.subarray(offset, offset + size)))
	}
	return out
}

function sendUdpQuery(message, dnsServer, timeoutMs) {
	const family = net.isIP(dnsServer.host) === 6 ? 'udp6' : 'udp4'
	return new Promise((resolve, reject) => {
		const socket = dgram.createSocket(family)
		const cleanup = () => {
			clearTimeout(timer)
			socket.close()
		}
		const timer = setTimeout(() => {
			cleanup()
			reject(new Error(`DNS query timed out (${formatDnsServer(dnsServer.host, dnsServer.port)})`))
		}, timeoutMs)
		timer.unref?.()
		socket.once('error', (error) => {
			cleanup()
			reject(error)
		})
		socket.once('message', (response) => {
			cleanup()
			try {
				validateDnsResponseHeader(response, message.readUInt16BE(0))
			} catch (error) {
				reject(error)
				return
			}
			resolve(response)
		})
		socket.send(message, dnsServer.port, dnsServer.host, (error) => {
			if (!error) return
			cleanup()
			reject(error)
		})
	})
}

function sendTcpQuery(message, dnsServer, timeoutMs) {
	const family = net.isIP(dnsServer.host)
	return new Promise((resolve, reject) => {
		const options = { host: dnsServer.host, port: dnsServer.port }
		if (family) options.family = family
		const socket = net.createConnection(options)
		const chunks = []
		let totalLength = 0
		let settled = false
		const cleanup = () => {
			clearTimeout(timer)
			socket.destroy()
		}
		const fail = (error) => {
			if (settled) return
			settled = true
			cleanup()
			reject(error)
		}
		const succeed = (response) => {
			if (settled) return
			settled = true
			cleanup()
			resolve(response)
		}
		const timer = setTimeout(() => {
			fail(new Error(`DNS query timed out (${formatDnsServer(dnsServer.host, dnsServer.port)})`))
		}, timeoutMs)
		timer.unref?.()
		socket.once('error', fail)
		socket.on('data', (chunk) => {
			if (settled) return
			chunks.push(chunk)
			totalLength += chunk.length
			if (totalLength < 4) return
			const payload = Buffer.concat(chunks, totalLength)
			const responseLength = payload.readUInt16BE(0)
			if (payload.length < responseLength + 2) return
			const response = payload.subarray(2, responseLength + 2)
			try {
				validateDnsResponseHeader(response, message.readUInt16BE(0))
			} catch (error) {
				fail(error)
				return
			}
			succeed(response)
		})
		socket.once('connect', () => {
			const frame = Buffer.allocUnsafe(message.length + 2)
			frame.writeUInt16BE(message.length, 0)
			message.copy(frame, 2)
			socket.end(frame)
		})
	})
}

function validateDnsResponseHeader(response, queryId) {
	if (response.length < 2 || response.readUInt16BE(0) !== queryId) {
		throw new Error('mismatched DNS response id')
	}
	if (response.length < 4 || (response.readUInt16BE(2) & DNS_FLAG_QR) === 0) {
		throw new Error('invalid DNS response: QR bit not set')
	}
}
function isTruncatedDnsResponse(response) {
	return response.length >= 4 && (response.readUInt16BE(2) & DNS_FLAG_TC) !== 0
}

async function sendDnsQuery(message, { server = null, port = 53, timeoutMs = 2000 } = {}) {
	const dnsServer = parseDnsServer(server || dns.getServers()[0], port)
	if (!dnsServer) throw new Error('no DNS server configured')
	const response = await sendUdpQuery(message, dnsServer, timeoutMs)
	const finalResponse = isTruncatedDnsResponse(response)
		? await sendTcpQuery(message, dnsServer, timeoutMs)
		: response
	const query = parseResponse(message)
	const parsed = parseResponse(finalResponse)
	if (parsed.questions.length < 1) throw new Error('invalid DNS response: missing question section')
	if (query.questions.length < 1) throw new Error('invalid DNS query: missing question section')
	const expected = query.questions[0]
	const actual = parsed.questions[0]
	if (actual.name !== expected.name || actual.type !== expected.type || actual.class !== expected.class) {
		throw new Error('mismatched DNS response question')
	}
	return finalResponse
}

function parseDnsServer(server, defaultPort) {
	if (!server) return null
	let host = server
	let port = defaultPort
	if (server.startsWith('[')) {
		const end = server.indexOf(']')
		if (end > 0) {
			host = server.slice(1, end)
			const suffix = server.slice(end + 1)
			if (suffix.startsWith(':')) {
				const parsedPort = Number(suffix.slice(1))
				if (Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 0xffff) port = parsedPort
			}
		}
	} else {
		const separator = server.lastIndexOf(':')
		if (separator > 0 && separator === server.indexOf(':')) {
			const parsedPort = Number(server.slice(separator + 1))
			if (Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 0xffff) {
				host = server.slice(0, separator)
				port = parsedPort
			}
		}
	}
	if (!host) return null
	return { host, port }
}

function formatDnsServer(host, port) {
	return net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`
}

function encodeName(name) {
	if (!name || name === '.') return Buffer.from([0])
	const normalized = name.endsWith('.') ? name.slice(0, -1) : name
	if (!normalized) return Buffer.from([0])
	const parts = []
	for (const label of normalized.split('.')) {
		const value = Buffer.from(label, 'utf8')
		parts.push(Buffer.from([value.length]), value)
	}
	parts.push(Buffer.from([0]))
	return Buffer.concat(parts)
}

function readName(buf, offset, seen = new Set()) {
	const labels = []
	let cursor = offset
	let nextOffset = offset
	let jumped = false
	while (true) {
		if (cursor >= buf.length) throw new Error('truncated DNS name')
		const length = buf[cursor]
		if ((length & 0xc0) === 0xc0) {
			if (cursor + 1 >= buf.length) throw new Error('truncated DNS name pointer')
			const pointer = ((length & 0x3f) << 8) | buf[cursor + 1]
			if (seen.has(pointer)) throw new Error('DNS name compression loop')
			if (!jumped) nextOffset = cursor + 2
			seen.add(pointer)
			cursor = pointer
			jumped = true
			continue
		}
		if (length === 0) {
			if (!jumped) nextOffset = cursor + 1
			break
		}
		cursor += 1
		const end = cursor + length
		if (end > buf.length) throw new Error('truncated DNS label')
		labels.push(buf.toString('utf8', cursor, end))
		cursor = end
	}
	return { name: labels.length ? labels.join('.') : '.', offset: nextOffset }
}

function formatIpv4(buf) {
	if (buf.length !== 4) throw new Error('invalid IPv4 length')
	return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
}

function formatIpv6(buf) {
	if (buf.length !== 16) throw new Error('invalid IPv6 length')
	const parts = []
	for (let offset = 0; offset < 16; offset += 2) {
		parts.push(buf.readUInt16BE(offset).toString(16))
	}
	return parts.join(':')
}

function u16(value) {
	const buf = Buffer.alloc(2)
	buf.writeUInt16BE(value, 0)
	return buf
}

module.exports = {
	TYPE,
	buildQuery,
	parseResponse,
	sendDnsQuery,
}
