// Fingerprint profile registry.
//
// hellojs ships with `chrome147-mac` as the canonical profile. To pin a different
// version (e.g. to keep up with Chrome's ~4-week cadence) or to ship a custom one,
// register it before the first request:
//
//   const profiles = require('@unreleased/hellojs/lib/profiles')
//   profiles.register('chrome148-mac', { name: 'chrome148-mac', ... })
//   request({ url, profile: 'chrome148-mac' })
//
// A profile is a plain object with the shape that lib/tls/tls.js, lib/headers.js, and
// lib/h3/transport-params.js consume. See ./chrome147-mac.js for the canonical shape.
// Validation here is intentionally minimal — we trust callers building these.

const profiles = {
	'chrome147-mac': require('./chrome147-mac'),
}

function get(name) {
	if (!name || name === 'default') name = 'chrome147-mac'
	const p = profiles[name]
	if (!p) throw new Error(`unknown profile: ${name}`)
	return p
}

function register(name, profile) {
	if (!name || typeof name !== 'string') throw new Error('profile name required')
	if (!profile || typeof profile !== 'object') throw new Error('profile must be an object')
	profiles[name] = profile
}

function list() { return Object.keys(profiles) }

const { fromPeet } = require('./from-peet')

// Parse a peet.ws response and register the resulting profile under `name`.
// Returns the registered profile so callers can inspect `profile.expected.ja4` etc.
function registerFromPeet(name, peetJson) {
	const profile = fromPeet(peetJson, { name })
	register(name, profile)
	return profile
}

module.exports = { get, list, register, registerFromPeet, fromPeet, profiles }
