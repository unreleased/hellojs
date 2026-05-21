// Unit test for TLS._profileNeedsMlkem — the gate that decides whether MLKEM keygen and
// key_share construction run during connect(). TLS-1.2-only / non-key_share profiles must
// not pay the MLKEM cost.

const test = require('node:test')
const assert = require('node:assert')
const { TLS } = require('../../lib/tls/tls')

function withProfile(tls) {
	// Synthesize a TLS instance with just enough state to invoke _profileNeedsMlkem().
	// We can't call new TLS('...') without a host, but we can instantiate the class normally
	// and overwrite this.profile to test each branch.
	const t = new TLS('example.com', 443)
	t.profile = { tls }
	return t._profileNeedsMlkem()
}

test('_profileNeedsMlkem: chrome147-default (no supportedVersions, no extensionOrder) → true', () => {
	assert.strictEqual(withProfile({}), true)
})

test('_profileNeedsMlkem: explicit supportedVersions incl. TLS 1.3 → true', () => {
	assert.strictEqual(withProfile({ supportedVersions: [0x0304, 0x0303] }), true)
})

test('_profileNeedsMlkem: TLS-1.2-only supportedVersions → false', () => {
	assert.strictEqual(withProfile({ supportedVersions: [0x0303] }), false)
})

test('_profileNeedsMlkem: extensionOrder without id 51 → false', () => {
	assert.strictEqual(withProfile({
		extensionOrder: [{ id: 0 }, { id: 10 }, { id: 43 }],
	}), false)
})

test('_profileNeedsMlkem: extensionOrder with id 51 → true', () => {
	assert.strictEqual(withProfile({
		extensionOrder: [{ id: 0 }, { id: 51 }, { id: 43 }],
	}), true)
})

test('_profileNeedsMlkem: GREASE markers in extensionOrder are skipped', () => {
	assert.strictEqual(withProfile({
		extensionOrder: [{ grease: true }, { id: 0 }, { id: 10 }],
	}), false)
})
