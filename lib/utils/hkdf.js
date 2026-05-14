// HKDF Helper functions
const crypto = require('crypto');


// const HASH = "sha256";
// const HASHLEN = 32;              // SHA-256 output



function Extract(hash, salt, ikm) {
  return crypto.createHmac(hash, salt).update(ikm).digest();
}

// HKDF-Expand with arbitrary info
function Expand(hash, prk, info, L, hashlen) {
  const n = Math.ceil(L / hashlen);
  const T = [];
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const h = crypto.createHmac(hash, prk);
    h.update(prev);
    h.update(info);
    h.update(Buffer.from([i])); // counter
    prev = h.digest();
    T.push(prev);
  }
  return Buffer.concat(T).subarray(0, L);
}

// RFC 8446: HKDF-Expand-Label(secret, label, context, L)
function ExpandLabel(secret, label, context, L, hash, hashlen) {
  const fullLabel = Buffer.from("tls13 " + label, "ascii")
  const ctx = Buffer.from(context || [])
  const info = Buffer.concat([
    // uint16 length
    Buffer.from([(L >> 8) & 0xff, L & 0xff]),
    // opaque label<7..255>
    Buffer.from([fullLabel.length]),
    fullLabel,
    // opaque context<0..255>
    Buffer.from([ctx.length]),
    ctx
  ])

  return Expand(hash, secret, info, L, hashlen);
}

function sha256(...bufs) {
  const h = crypto.createHash("sha256")
  bufs.forEach(b => h.update(b))
  return h.digest()
}

function sha384(...bufs) {
  const h = crypto.createHash("sha384")
  bufs.forEach(b => h.update(b))
  return h.digest()
}

module.exports = {
	Extract,
	Expand,
	ExpandLabel,
	sha256,
	sha384
}