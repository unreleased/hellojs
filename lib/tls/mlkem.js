// X25519MLKEM768 hybrid (draft-kwiatkowski-tls-ecdhe-mlkem-02) for TLS 1.3 group 0x11EC.
//
// Wire layout:
//   client_share = MLKEM768_pk(1184) || X25519_pk(32)            = 1216 bytes
//   server_share = MLKEM768_ct(1088) || X25519_pk(32)            = 1120 bytes
//   shared_secret = MLKEM_ss(32) || X25519_ss(32)                = 64 bytes
//
// Note ordering: MLKEM portion comes FIRST in both client/server shares and in the
// concatenated shared secret. The X25519 portion follows.

// We need a fully-synchronous keygen path on the hot path. The public `mlkem` exports are:
//   - `MlKem768` (deprecated async wrapper, every method returns a Promise)
//   - `createMlKem768()` (factory that returns a Promise<MlKem768Impl>)
// The `MlKem768Impl` class itself has SYNC methods but its `_setup()` is async (loads
// `globalThis.crypto`). On Node 19+ globalThis.crypto is always available synchronously.
// So we deep-load the impl module via require.resolve() and instantiate it directly with
// `_api` set manually — no async setup, no microtask hops.
const path = require('path')
const { MlKem768Impl } = require(path.join(path.dirname(require.resolve('mlkem')), 'src/mlKem768Impl.js'))

function newImpl() {
	const k = new MlKem768Impl()
	k._api = globalThis.crypto    // skip the async _setup()
	return k
}
const crypto = require('crypto')

const MLKEM_PK_LEN = 1184
const MLKEM_CT_LEN = 1088
const X25519_LEN = 32

// Keep an async signature for forward compatibility (e.g. if we move keygen to a worker).
// Today the body is purely sync.
async function generateMlKemKeyPair() {
	return generateMlKemKeyPairSync()
}

function generateMlKemKeyPairSync() {
	const k = newImpl()
	const [pk, sk] = k.generateKeyPair()
	return { pk: Buffer.from(pk), sk: Buffer.from(sk) }
}

// Pre-generated keypair pool. ML-KEM-768 keygen takes ~8ms cold and drops to ~0.5ms
// after V8 JIT warms up. Doing it on the hot path of TLS.connect() blocks the first
// network write. The pool generates keypairs on idle ticks (setImmediate) and connect()
// can grab a finished one. Capped at POOL_SIZE.
const POOL_SIZE = 4
const pool = []                              // [{pk, sk}, …] — completed keypairs
const inflight = []                          // [Promise<{pk, sk}>, …] — in-progress generations

function refill() {
	while (pool.length + inflight.length < POOL_SIZE) {
		// setImmediate so the keygen doesn't compete with whatever's on the event loop now.
		const p = new Promise((resolve) => {
			setImmediate(async () => {
				try { resolve(await generateMlKemKeyPair()) }
				catch (_) { resolve(null) }
			})
		})
		inflight.push(p)
		p.then((kp) => {
			const idx = inflight.indexOf(p); if (idx >= 0) inflight.splice(idx, 1)
			if (kp) pool.push(kp)
		})
	}
}

// Get a pre-generated keypair. Order of preference:
//   1. A completed keypair from the pool — instant.
//   2. An in-flight keypair generation that's in progress (started by prime or refill) —
//      cheaper than starting a new one because the work is already underway.
//   3. Start a brand-new generation on the spot — last resort.
async function acquireMlKemKeyPair() {
	const ready = pool.shift()
	refill()
	if (ready) return ready
	// Take ownership of the oldest in-flight gen so we don't double-spend keygen work.
	if (inflight.length > 0) {
		const p = inflight[0]
		const kp = await p
		// Pull `p` out of inflight if it's still there — note: the .then(...) below may have
		// already removed it. Either way, claim its result.
		const idx = inflight.indexOf(p); if (idx >= 0) inflight.splice(idx, 1)
		if (kp) return kp
	}
	return generateMlKemKeyPair()
}

// Sync-prime ONE keypair at module load. Costs ~8ms ADDED to require() but moves the
// equivalent cost OFF the first-request critical path. Subsequent refills use setImmediate.
// Opt out via HELLOJS_NO_PREWARM=1 — useful for CLI apps where startup latency matters
// more than first-request latency.
if (!process.env.HELLOJS_NO_PREWARM) {
	try { pool.push(generateMlKemKeyPairSync()) } catch (_) {}
	refill()
}

async function decapsulateMlKem(ct, sk) {
	const k = newImpl()
	return Buffer.from(k.decap(ct, sk))
}

// Given the server's 1120-byte X25519MLKEM768 key_share entry and our private keys, compute the 64-byte hybrid shared secret.
async function deriveHybridSharedSecret(serverShareBuf, clientMlKemSk, clientX25519PrivateKey) {
	if (serverShareBuf.length !== MLKEM_CT_LEN + X25519_LEN) {
		throw new Error(`unexpected X25519MLKEM768 server_share length ${serverShareBuf.length}, want ${MLKEM_CT_LEN + X25519_LEN}`)
	}
	const mlkemCt = serverShareBuf.subarray(0, MLKEM_CT_LEN)
	const serverX25519Raw = serverShareBuf.subarray(MLKEM_CT_LEN)

	const mlkemSs = await decapsulateMlKem(mlkemCt, clientMlKemSk)

	const hdr = Buffer.from('302a300506032b656e032100', 'hex')
	const serverX25519Spki = Buffer.concat([hdr, serverX25519Raw])
	const serverPub = crypto.createPublicKey({ type: 'spki', format: 'der', key: serverX25519Spki })
	const x25519Ss = crypto.diffieHellman({ publicKey: serverPub, privateKey: clientX25519PrivateKey })

	return Buffer.concat([mlkemSs, x25519Ss])
}

module.exports = {
	generateMlKemKeyPair,
	acquireMlKemKeyPair,
	decapsulateMlKem,
	deriveHybridSharedSecret,
	MLKEM_PK_LEN,
	MLKEM_CT_LEN,
	X25519_LEN,
}
