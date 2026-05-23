const test = require('node:test')
const assert = require('node:assert')
const {
	SUPPORTED_ECH_VERSION,
	parseECHConfigList,
	parseRetryConfigs,
	selectECHConfig,
	selectECHCipherSuite,
} = require('../../lib/tls/ech-config')
const { setupBaseSender } = require('../../lib/tls/ech-hpke')

function u8(value) {
	return Buffer.from([value])
}

function u16(value) {
	const buf = Buffer.alloc(2)
	buf.writeUInt16BE(value, 0)
	return buf
}

function opaque8(bytes) {
	return Buffer.concat([u8(bytes.length), bytes])
}

function opaque16(bytes) {
	return Buffer.concat([u16(bytes.length), bytes])
}

function buildConfigContents({
	configId = 7,
	kemId = 0x0020,
	publicKey = Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
	cipherSuites = [{ kdfId: 0x0001, aeadId: 0x0001 }],
	maximumNameLength = 0,
	publicName = 'public.example',
	extensions = Buffer.alloc(0),
}) {
	const suites = Buffer.concat(cipherSuites.map((suite) => Buffer.concat([
		u16(suite.kdfId),
		u16(suite.aeadId),
	])))
	return Buffer.concat([
		u8(configId),
		u16(kemId),
		opaque16(publicKey),
		opaque16(suites),
		u8(maximumNameLength),
		opaque8(Buffer.from(publicName, 'ascii')),
		opaque16(extensions),
	])
}

function buildECHConfig(version, contents) {
	return Buffer.concat([u16(version), opaque16(contents)])
}

function buildECHConfigList(configs) {
	const body = Buffer.concat(configs)
	return Buffer.concat([u16(body.length), body])
}

test('parses a supported RFC 9849 ECHConfigList entry', () => {
	const contents = buildConfigContents({
		configId: 9,
		publicKey: Buffer.from('aabbccdd', 'hex'),
		cipherSuites: [
			{ kdfId: 0x0002, aeadId: 0x0002 },
			{ kdfId: 0x0001, aeadId: 0x0001 },
		],
		maximumNameLength: 12,
		publicName: 'Public.Example',
		extensions: Buffer.concat([u16(0xff20), opaque16(Buffer.from('beef', 'hex'))]),
	})
	const rawConfig = buildECHConfig(SUPPORTED_ECH_VERSION, contents)
	const configs = parseECHConfigList(buildECHConfigList([rawConfig]))

	assert.strictEqual(configs.length, 1)
	assert.strictEqual(configs[0].version, SUPPORTED_ECH_VERSION)
	assert.strictEqual(configs[0].supportedVersion, true)
	assert.strictEqual(configs[0].configId, 9)
	assert.strictEqual(configs[0].kemId, 0x0020)
	assert.deepStrictEqual(configs[0].publicKey, Buffer.from('aabbccdd', 'hex'))
	assert.deepStrictEqual(configs[0].cipherSuites, [
		{ kdfId: 0x0002, aeadId: 0x0002 },
		{ kdfId: 0x0001, aeadId: 0x0001 },
	])
	assert.strictEqual(configs[0].maximumNameLength, 12)
	assert.strictEqual(configs[0].publicName, 'public.example')
	assert.deepStrictEqual(configs[0].publicNameBytes, Buffer.from('Public.Example', 'ascii'))
	assert.deepStrictEqual(configs[0].extensions, Buffer.concat([u16(0xff20), opaque16(Buffer.from('beef', 'hex'))]))
	assert.deepStrictEqual(configs[0].raw, rawConfig)
})

test('keeps unsupported versions as opaque raw configs', () => {
	const rawConfig = buildECHConfig(0xffff, Buffer.from('010203', 'hex'))
	const [config] = parseECHConfigList(buildECHConfigList([rawConfig]))

	assert.strictEqual(config.version, 0xffff)
	assert.strictEqual(config.supportedVersion, false)
	assert.deepStrictEqual(config.raw, rawConfig)
	assert.deepStrictEqual(config.contents, Buffer.from('010203', 'hex'))
	assert.strictEqual('configId' in config, false)
})

test('parseRetryConfigs reuses ECHConfigList parsing', () => {
	const rawConfig = buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({ configId: 3 }))
	const parsed = parseRetryConfigs(buildECHConfigList([rawConfig]))

	assert.strictEqual(parsed.length, 1)
	assert.strictEqual(parsed[0].configId, 3)
})

test('selects the first supported config and first supported cipher suite', () => {
	const selected = selectECHConfig([
		{ version: 0xffff, raw: Buffer.from('aa', 'hex') },
		{
			version: SUPPORTED_ECH_VERSION,
			configId: 4,
			kemId: 0x0020,
			cipherSuites: [
				{ kdfId: 0x0002, aeadId: 0x0001 },
				{ kdfId: 0x0001, aeadId: 0x0001 },
			],
		},
		{
			version: SUPPORTED_ECH_VERSION,
			configId: 5,
			kemId: 0x0020,
			cipherSuites: [{ kdfId: 0x0001, aeadId: 0x0001 }],
		},
	])

	assert.strictEqual(selected.configId, 4)
	assert.deepStrictEqual(selectECHCipherSuite(selected), { kdfId: 0x0001, aeadId: 0x0001 })
})

test('returns null when no config matches supported KEM and cipher suite policy', () => {
	const selected = selectECHConfig([
		{
			version: SUPPORTED_ECH_VERSION,
			configId: 7,
			kemId: 0x0010,
			cipherSuites: [{ kdfId: 0x0001, aeadId: 0x0001 }],
		},
		{
			version: SUPPORTED_ECH_VERSION,
			configId: 8,
			kemId: 0x0020,
			cipherSuites: [{ kdfId: 0x0003, aeadId: 0x0003 }],
		},
	])

	assert.strictEqual(selected, null)
})

test('rejects truncated and empty ECHConfigList values plus invalid public names', () => {
	assert.throws(() => parseECHConfigList(Buffer.from('0004fe0d', 'hex')), /invalid ECHConfigList length|truncated ECHConfig/)
	assert.throws(() => parseECHConfigList(Buffer.from('0000', 'hex')), /ECHConfigList must contain at least one config/)

	const invalidName = buildECHConfigList([
		buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({ publicName: 'bad..name' })),
	])
	assert.throws(() => parseECHConfigList(invalidName), /invalid ECHConfig public_name/)
})


test('parsed supported configs are stable snapshots of the input bytes', () => {
	const list = buildECHConfigList([
		buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({
			publicKey: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
			extensions: Buffer.concat([u16(0xff10), opaque16(Buffer.from('0001', 'hex'))]),
		})),
	])
	const parsed = parseECHConfigList(list)[0]
	const keyOffset = list.indexOf(Buffer.from('00112233445566778899aabbccddeeff', 'hex'))
	list.fill(0xff, keyOffset, keyOffset + 16)
	assert.deepStrictEqual(parsed.publicKey, Buffer.from('00112233445566778899aabbccddeeff', 'hex'))
	assert.deepStrictEqual(parsed.extensions, Buffer.concat([u16(0xff10), opaque16(Buffer.from('0001', 'hex'))]))
})

test('setupBaseSender rejects KDF/AEAD overrides that are not offered by the config', async () => {
	const config = selectECHConfig(parseECHConfigList(buildECHConfigList([
		buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({})),
	])))
	await assert.rejects(
		() => setupBaseSender(config, { kdfId: 0x0003, aeadId: 0x0001 }),
		/ECH cipher suite 0x3\/0x1 not offered by config/,
	)
})

test('rejects duplicate ECHConfig extensions and skips configs with unsupported extensions', () => {
	const dupExtensions = Buffer.concat([
		u16(0xff01), opaque16(Buffer.from('aa', 'hex')),
		u16(0xff01), opaque16(Buffer.from('bb', 'hex')),
	])
	const dupList = buildECHConfigList([
		buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({ extensions: dupExtensions })),
	])
	assert.throws(() => parseECHConfigList(dupList), /duplicate ECHConfig extension 0xff01/)

	const unknownExtensions = Buffer.concat([
		u16(0xff02), opaque16(Buffer.from('cc', 'hex')),
	])
	const configs = parseECHConfigList(buildECHConfigList([
		buildECHConfig(SUPPORTED_ECH_VERSION, buildConfigContents({ extensions: unknownExtensions })),
	]))
	assert.strictEqual(configs[0].hasUnsupportedExtensions, true)
	assert.strictEqual(selectECHConfig(configs), null)
})
