# @conorre/hellojs

A Node.js HTTP client whose on-the-wire TLS handshake, HTTP/2 setup, and
HTTP/3 (QUIC) flight produces **the same JA4 / Akamai / peetprint
fingerprint as Chrome 147 on macOS**. Drop-in
[`request`](https://github.com/request/request)-shape API.

```bash
npm install @conorre/hellojs
```

```js
const request = require('@conorre/hellojs')

const html = await request('https://www.cloudflare.com/')

const res = await request({
  url: 'https://api.example.com/v1/things',
  method: 'POST',
  headers: { authorization: 'Bearer …' },
  json: { name: 'foo' },
  resolveWithFullResponse: true,
})
```

---

## Table of contents

- [Why](#why)
- [Quick start](#quick-start)
- [Request options](#request-options)
- [Method shortcuts and defaults](#method-shortcuts-and-defaults)
- [Cookie jar](#cookie-jar)
- [Connection pool](#connection-pool)
- [Proxies](#proxies)
- [Observability hooks](#observability-hooks)
- [Parrot: clone any fingerprint](#parrot-clone-any-fingerprint-from-a-tlspeetws-response)
- [Fingerprint](#fingerprint)
- [HTTP/3](#http3)
- [Session resumption and 0-RTT](#session-resumption-and-0-rtt)
- [Certificate validation](#certificate-validation)
- [TypeScript](#typescript)
- [Performance](#performance)
- [Errors](#errors)
- [Debugging](#debugging)
- [API surface](#api-surface)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Why

`undici`, `axios`, `got`, `node-fetch`, etc. all emit a TLS / H2 / H3
fingerprint that is unmistakably Node.js:

- Cipher list ordered for OpenSSL defaults, not the BoringSSL shape Chrome ships
- No GREASE values
- No ALPS (application_settings) extension
- No `X25519MLKEM768` hybrid key share
- HTTP/2 SETTINGS in the wrong order, no `WINDOW_UPDATE +15663105`
- Different HEADERS frame flags
- Different `:method` / `:authority` / `:scheme` / `:path` pseudo-header order

Any bot-detection service (Cloudflare Bot Management, PerimeterX, DataDome,
Akamai Bot Manager, …) can identify Node-based traffic from the JA4
fingerprint alone, regardless of what `User-Agent` header you set.

hellojs produces:

```
JA4               = t13d1516h2_8daaf6152771_d8a2da3f94cd
HTTP/2 Akamai     = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
ALPS              = h2 (v1, type 0x44CD)
key_share         = X25519MLKEM768 + X25519 + GREASE (1216-byte hybrid share)
extension order   = GREASE-first, per-instance shuffled middle, GREASE-last
```

…all matching a real Chrome 147 capture on every structural fingerprint hash
(JA4, Akamai, peetprint). Per-connection randomized fields (GREASE values,
`client_random`, key_share bytes, extension shuffle order) rotate every
handshake — same as a real Chrome browser.

---

## Quick start

```js
const request = require('@conorre/hellojs')

// GET, body returned as Buffer (or string if content-type says utf-8, or
// object if json:true)
const body = await request({ url: 'https://httpbingo.org/get' })

// POST with JSON
const res = await request({
  url: 'https://httpbingo.org/post',
  method: 'POST',
  json: { hello: 'world' },
})

// Full response
const r = await request({
  url: 'https://httpbingo.org/status/418',
  simple: false,
  resolveWithFullResponse: true,
})
console.log(r.status, r.headers, r.body)

// POST form
await request({
  url: 'https://httpbingo.org/post',
  method: 'POST',
  form: { user: 'alice', role: 'admin' },
})

// Query string
await request({
  url: 'https://httpbingo.org/get',
  qs: { hello: 'world', n: 42 },
})
```

---

## Request options

| Option | Type | Default | Notes |
|---|---|---|---|
| `url` / `uri` | string | required | |
| `method` | string | `'GET'` | |
| `headers` | object | `{}` | merged into the Chrome 147 default header set; user-supplied keys win on conflict |
| `body` | string \| Buffer \| object \| Readable | `null` | object → JSON when `json: true`. A Node `Readable` is sent as a streaming request body (chunked h2 DATA frames or h1 `Transfer-Encoding: chunked`). |
| `json` | bool \| object | `false` | parses response as JSON; if object, used as the request body with `content-type: application/json` |
| `form` | object | — | `application/x-www-form-urlencoded` body |
| `qs` | object | — | querystring appended to url |
| `jar` | `request.jar()` | — | cookie persistence across requests |
| `gzip` | bool | `false` | auto-decompress gzip/br/deflate/zstd response bodies |
| `followRedirect` | bool | `true` | up to `maxRedirects` |
| `maxRedirects` | number | `10` | |
| `timeout` | ms | — | aborts request after N ms (legacy single-phase timer; applies to the response phase) |
| `timeouts` | object | — | per-phase timeouts: `{ connect, tlsHandshake, response, idle }`, all in ms. Overrides `timeout` for the response phase. |
| `proxy` | URL string | — | HTTP CONNECT proxy: `http://user:pass@host:port` |
| `forever` | bool | `true` | reuse pooled TLS connections; `false` forces fresh handshake |
| `simple` | bool | `true` | reject 4xx/5xx as errors (set `false` to resolve them as responses) |
| `resolveWithFullResponse` | bool | `false` | resolve to `{status, headers, body}` instead of just body |
| `retry` | object | none | `{ limit, methods, statusCodes, baseDelayMs }` |
| `profile` | string | `'chrome147-mac'` | which fingerprint profile to emit |
| `h3` | bool | — | force HTTP/3 (`true`) or disable auto-upgrade (`false`); unset = auto via Alt-Svc |
| `earlyData` | Buffer \| string | — | TLS 1.3 0-RTT bytes — see [Session resumption and 0-RTT](#session-resumption-and-0-rtt) |
| `verifyTLS` | bool | `true` | Validate the server certificate chain (RFC 5280) + hostname (RFC 6125 SubjectAltName). On by default. Set `false` to skip validation (self-signed dev servers, intentional MITM proxies). Applies to both TLS 1.3 and TLS 1.2 paths. See [Certificate validation](#certificate-validation). |

---

## Method shortcuts and defaults

```js
await request.get('https://httpbingo.org/get')
await request.post({ url: 'https://httpbingo.org/post', body: '...' })
await request.put({ url: '...', json: { … } })
await request.del('https://...')
await request.patch({ url: '...', form: { … } })
await request.head('https://...')
await request.options('https://...')

const api = request.defaults({
  headers: { 'x-api-key': '…' },
  json: true,
  resolveWithFullResponse: true,
})

const r = await api({ url: 'https://api.example.com/users' })
const r2 = await api.get('https://api.example.com/things/42')
```

---

## Cookie jar

RFC 6265-compliant. Domain matching, path matching, `Secure`/`HttpOnly`/`SameSite`,
`Expires`/`Max-Age`, host-only vs domain cookies, longest-path-first ordering, public
suffix list defense.

```js
const jar = request.jar()

await request({
  url: 'https://example.com/login',
  jar, method: 'POST',
  form: { user: '…', pass: '…' },
})

// Subsequent requests sharing the same jar send saved cookies automatically.
// Domain matching, path matching, Secure on https-only, all honored.
const me = await request({ url: 'https://example.com/account', jar, json: true })
```

To defend against supercookies (`Domain=co.uk`), plug in a public suffix list:

```js
const jar = request.jar()
// A Set or a function(host) -> boolean
jar.setPublicSuffixList(new Set(['co.uk', 'github.io', /* ... */]))
```

The jar drops expired cookies automatically on read; call `jar.gc()` to bound memory
under high churn.

---

## Connection pool

By default `request()` reuses pooled TLS+H2 connections to the same origin:

```js
// First call opens a TLS handshake → H2 session
await request({ url: 'https://example.com/a' })

// Second call to the same origin reuses the same H2 session (no handshake)
await request({ url: 'https://example.com/b' })

// Force a fresh handshake
await request({ url: 'https://example.com/a', forever: false })
```

Pool internals:

- Keyed by `(transport, host:port, profile, proxy)`
- 5-minute idle timeout (evicts inactive connections)
- 6 simultaneous fresh-handshake connections per host (matches Chrome). Pooled
  multiplexed connections are not capped by this.
- H2 connections multiplex; H1 connections are single-use, kept warm via TCP keep-alive
- Per-origin in-flight handshake deduplication: concurrent first requests to a new host share one handshake
- Happy Eyeballs v2 (RFC 8305) — races IPv4 + IPv6 with a 250ms head start for v6;
  broken-IPv6 networks no longer pay full SYN timeouts

```js
// Tune limits per Pool instance:
const { Pool } = require('@conorre/hellojs')
const myPool = new Pool({ idleTimeoutMs: 60_000, maxPerHost: 12 })
```

### Graceful shutdown

`pool.shutdown(timeoutMs)` waits for in-flight requests to settle before closing the
sockets. New `request()` calls are rejected with `EPROTO` during the drain. After the
deadline, any remaining in-flight is forcefully closed.

```js
process.on('SIGTERM', async () => {
  await request.pool.shutdown(30_000)
  process.exit(0)
})
```

For abrupt shutdown:

```js
request.pool.closeAll()
```

### Per-phase timeouts

```js
await request({
  url: 'https://api.example.com/v1/things',
  timeouts: {
    connect:      2_000,   // TCP connect must complete within 2s
    tlsHandshake: 5_000,   // TLS 1.2/1.3 handshake completion deadline
    response:    10_000,   // First byte / full response deadline
    idle:        60_000,   // How long the pooled connection sits idle before close
  },
})
```

If only the legacy `timeout` option is set, it applies to the response phase.

### Streaming response bodies

Pass `stream: true` and the promise resolves as soon as headers arrive, with the
response body as a Node `Readable`. The body auto-decompresses (gzip / brotli /
deflate; zstd requires Node 23.8+ for streaming).

```js
const { createWriteStream } = require('node:fs')
const body = await request({
  url: 'https://example.com/big.iso',
  stream: true,
})
body.pipe(createWriteStream('./big.iso'))

// Or with full response shape:
const res = await request({
  url: 'https://example.com/big.iso',
  stream: true,
  resolveWithFullResponse: true,
})
console.log(res.statusCode, res.headers['content-length'])
res.body.pipe(createWriteStream('./big.iso'))
```

### Streaming request bodies

For large uploads, pass a Node `Readable` as `body`. On h2 it streams as DATA
frames; on h1 it streams via `Transfer-Encoding: chunked`.

```js
const { createReadStream } = require('node:fs')
await request({
  url: 'https://upload.example.com/blob',
  method: 'POST',
  body: createReadStream('./big-file.bin'),
  headers: { 'content-type': 'application/octet-stream' },
})
```

### Persistent session cache

By default the TLS session cache (used to enable PSK resumption and 0-RTT) is
in-memory and reset on process exit. Point it at a file to persist across
restarts:

```bash
HELLOJS_SESSION_CACHE=/var/cache/hellojs-sessions.json node my-script.js
```

Or in JS:

```js
require('@conorre/hellojs/lib/tls/session-cache').enablePersistence({
  path: '/var/cache/hellojs-sessions.json',
})
```

The file holds NewSessionTicket material, is written with mode `0600`, and uses an
`O_EXCL` lock so two processes pointed at the same file merge their tickets instead
of clobbering. Stale locks (older than 30s, e.g. from a crashed writer) are reclaimed
automatically. Expired tickets are filtered out on load.

---

## Proxies

### HTTP CONNECT

```js
await request({ url: 'https://example.com', proxy: 'http://user:pass@proxy:8080' })
```

Basic auth credentials in the URL are auto-encoded into `Proxy-Authorization`.

### SOCKS5 (RFC 1928 + RFC 1929)

```js
await request({ url: 'https://example.com', proxy: 'socks5://user:pass@proxy:1080' })
await request({ url: 'https://example.com', proxy: 'socks5://proxy:1080' })  // no-auth
```

`socks5h://` is accepted as an alias. We always do remote DNS resolution (the proxy
resolves the hostname), not client-side, regardless of the scheme.

---

## Observability hooks

Subscribe to request lifecycle events for metrics, tracing, or SLO tracking. Hook
exceptions are swallowed — they never break the request.

```js
const request = require('@conorre/hellojs')

request.observability.on('request:end', (ev) => {
  console.log(`req ${ev.id} ${ev.status} in ${ev.durationMs}ms; ${ev.totalBytes}B`)
})

request.observability.on('request:firstByte', (ev) => {
  histogram.observe('ttfb_ms', ev.durationMs)
})
```

Available events: `request:start`, `request:headersSent`, `request:firstByte`,
`request:end`, `request:error`. Each carries a numeric `id` so a hook can correlate
events for the same request.

---

## Parrot: clone any fingerprint from a tls.peet.ws response

Paste a [tls.peet.ws/api/all](https://tls.peet.ws/api/all) JSON response into
`profiles.registerFromPeet()` and hellojs will mimic that fingerprint:

```js
const fs = require('node:fs')
const request = require('@conorre/hellojs')

const peetJson = JSON.parse(fs.readFileSync('./captured.json', 'utf8'))
request.profiles.registerFromPeet('chrome148-mac', peetJson)

const r = await request({ url: 'https://tls.peet.ws/api/all', profile: 'chrome148-mac', json: true })
// r.tls.ja4 will equal peetJson.tls.ja4
// r.http2.akamai_fingerprint_hash will equal peetJson.http2.akamai_fingerprint_hash
```

What gets cloned (the structural fingerprint — JA4, akamai_fingerprint, peetprint):
cipher list, extension presence, supported_groups, supported_versions, signature_algorithms,
key_share group selection, ALPN order, ALPS extension type + protocols, cert compression,
HTTP/2 SETTINGS, WINDOW_UPDATE increment, HEADERS priority flag, pseudo-header order, and
the default request header set.

What is **not** cloned (these rotate per-handshake on purpose):

- Specific GREASE codepoints (Chrome picks fresh ones each handshake)
- `client_random`, `session_id`, `key_share` bytes
- ECH config bytes (per-handshake; we send a GREASE ECH instead)
- Extension order **within** the middle block — Chrome shuffles this per TLS instance, so
  JA3 (which hashes extensions in wire order) legitimately varies connection-to-connection
  from the **same** profile. JA4 sorts before hashing, so JA4 is stable.

This is the same behaviour as a real Chrome browser: open Wireshark and capture two
back-to-back handshakes from the same Chrome instance — the JA4 will match, the JA3 won't.

---

## Fingerprint

The default profile, `chrome147-mac`, was captured from a real Chrome 147 install
on macOS and lives at [`lib/profiles/chrome147-mac.js`](lib/profiles/chrome147-mac.js).
To clone any other fingerprint, see [Parrot](#parrot-clone-any-fingerprint-from-a-tlspeetws-response).
The profile defines:

- Cipher list (16 entries, including TLS 1.2 padding suites)
- Per-instance extension permutation (GREASE-pinned at boundaries, middle shuffled deterministically from `client_random`)
- Signature algorithms (8 entries, exact order)
- Supported groups: GREASE, X25519MLKEM768, X25519, P-256, P-384
- Key share: hybrid X25519MLKEM768 (1216 B) + X25519 (32 B) + GREASE
- ALPS extension type 0x44CD (v1) advertising h2
- compress_certificate: brotli only
- HTTP/2 SETTINGS values + insertion order
- HTTP/2 WINDOW_UPDATE +15663105 on stream 0
- Default header set + ordering matching Chrome 147's `accept` / `sec-fetch-*` / `priority` etc.

### Verifying

```bash
node test/fingerprint/chrome147.js
```

Asserts JA4, Akamai HTTP/2 fingerprint, cipher list, signature_algorithms,
supported_groups, supported_versions, extension set, HTTP/2 HEADERS flags +
header order against `test/fixtures/chrome147-peet.json` (a real Chrome 147
capture on macOS via [tls.peet.ws](https://tls.peet.ws)).

Expected output: `11/11 checks passed` and
`JA4 == t13d1516h2_8daaf6152771_d8a2da3f94cd`.

---

## HTTP/3

Pure-JS QUIC + HTTP/3 client at `lib/h3/`, integrated into `request()`:

```js
// Explicit h3
await request({ url: 'https://www.cloudflare.com/', h3: true })

// Automatic upgrade via Alt-Svc — first request goes h2, captures
// `alt-svc: h3=":443"`, subsequent same-host requests transparently use h3
// (Chrome behaviour)
await request({ url: 'https://www.cloudflare.com/' })          // h2
await request({ url: 'https://www.cloudflare.com/api/foo' })   // h3 (auto)

// Disable h3 explicitly
await request({ url: '...', h3: false })
```

Or use the lower-level QUIC + H3 layer directly:

```js
const { QuicConnection } = require('@conorre/hellojs/lib/h3/connection')
const { H3Client } = require('@conorre/hellojs/lib/h3/h3')

const conn = new QuicConnection('cloudflare-quic.com', 443)
conn.on('ready', async () => {
  const res = await new H3Client(conn).request({
    method: 'GET',
    path: '/',
    host: 'cloudflare-quic.com',
  })
  console.log(res.status, res.headers, res.body.length)
  conn.close()
})
await conn.connect()
```

### What's implemented

- **QUIC v1 packet protection** (Initial / Handshake / 1-RTT) — AEAD payload + header protection. RFC 9001 Appendix A test vectors pass byte-perfect.
- **AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305** AEAD + matching header protection (AES-ECB / ChaCha20 stream).
- **Retry packet handling** (RFC 9000 §17.2.5).
- **Loss recovery**: per-epoch sent-packet log, ACK frame parsing with multi-range support, PTO timer with exponential backoff.
- **NewReno congestion control** (RFC 9002) on the 1-RTT epoch — slow start, congestion avoidance, recovery on PTO.
- **TLS 1.3 key updates** (RFC 9001 §6) — server-initiated phase rotation, pre-derived next keys, commit-on-decrypt-success.
- **DATAGRAM extension** (RFC 9221) — both 0x30 + 0x31 forms, peer transport-parameter parsing, `conn.sendDatagram(buf)`.
- **NEW_CONNECTION_ID rotation** (RFC 9000 §5.1) — parse + stash + retire_prior_to semantics, `conn.rotateConnectionId()`.
- **Path validation** (RFC 9000 §8.2) — auto-respond to PATH_CHALLENGE, `conn.validatePath()` round-trips.
- **QPACK static table + dynamic-table decode** — server's encoder stream is consumed into a local replica; HEADERS decode against both.
- **Alt-Svc auto-upgrade** — h2 responses' `alt-svc: h3=":443"; ma=N` cached, subsequent same-host requests transparently use h3.
- **Graceful CONNECTION_CLOSE** on close.

### What's not implemented

- **Client-initiated key updates** — we follow the peer's rotation; we don't trigger our own based on a packets-per-key threshold.
- **CUBIC / BBR congestion control** — NewReno only.
- **QPACK encoder-side dynamic table** — our outbound encoder is static-only (slightly larger request headers).
- **Full connection migration** — path validation works, but we don't rebind the UDP socket to a new local 4-tuple.
- **0-RTT over QUIC** — TLS-over-TCP 0-RTT is implemented end-to-end (see below); QUIC 0-RTT-Protected packets aren't yet wired.

### Server compatibility

| Server | Result |
|---|---|
| `cloudflare-quic.com` | ✅ |
| `www.cloudflare.com` | ✅ |
| `quic.aiortc.org` | ✅ |
| `www.google.com` | timeout (likely MTU/firewall on test network) |
| `cloud.google.com` | timeout |

---

## Session resumption and 0-RTT

`NewSessionTicket` frames the server sends post-handshake are parsed and
cached in-memory (keyed by host). Subsequent `request()` calls automatically
offer the cached PSK on ClientHello — handshake skips the cert chain and the
`pre_shared_key` echo confirms resumption:

```js
// Pass 1: cold connect; server sends NewSessionTickets, cached automatically
await request({ url: 'https://www.cloudflare.com/', forever: false })

// Pass 2: auto-uses the cached PSK. Smaller CH, no cert chain.
await request({ url: 'https://www.cloudflare.com/', forever: false })
```

### Real 0-RTT (early data)

Bytes encrypted under the 0-RTT traffic keys and sent in the same flight
as ClientHello — server can start processing **before** the handshake
completes:

```js
// ONLY safe for idempotent / replay-tolerant operations (RFC 8470)
await request({
  url: 'https://example.com/api/foo',
  earlyData: Buffer.from('GET /api/foo HTTP/1.1\r\nHost: example.com\r\n\r\n'),
  forever: false,
})
```

The implementation covers:

- PSK extension with binder HMAC over the partial-CH transcript hash
- `client_early_traffic_secret` derivation
- 0-RTT `application_data` records sent right after the dummy CCS
- `EndOfEarlyData` handshake message when the server accepts
- Replay-over-1-RTT when the server rejects (no `early_data` echo in EE)

### h2 0-RTT encoder helper

Most servers negotiate h2, so raw bytes need to be h2-framed, not h1.
`request.encodeH2EarlyData()` produces the byte sequence Chrome would send:

```js
const earlyData = request.encodeH2EarlyData({
  method: 'GET',
  path: '/api/foo',
  host: 'example.com',
  headers: { 'user-agent': 'my-app/1.0' },
})

// What it returns (126 B for a typical GET):
//   PREFACE (24 B)
//   SETTINGS frame on stream 0
//   WINDOW_UPDATE +15663105 on stream 0
//   HEADERS frame on stream 1 with END_HEADERS | END_STREAM, HPACK-encoded
//   (static-table indexed + Huffman string literals)
```

The helper **refuses non-idempotent methods** (POST/PUT/PATCH/DELETE) — see
RFC 8470 for why.

> **Caveat on reading the response:** `request()` uses its own H/2 session
> for the 1-RTT path and that session sends its own preface after the
> handshake. If you pass real h2 early-data, the server has already started
> processing your request on stream 1 — but the subsequent `request()` GET
> opens stream 3, not stream 1, so the 0-RTT response is unread. To consume
> the 0-RTT response, drop down to `TLS` + your own frame parser:
>
> ```js
> const { TLS } = require('@conorre/hellojs')
> const sessionCache = require('@conorre/hellojs/lib/tls/session-cache')
>
> const session = sessionCache.peek('example.com')
> const tls = new TLS('example.com', 443, null, { session, earlyData })
> tls.on('ready', () => {
>   // tls.h2Transport is a Duplex of decrypted h2 frames — feed it into
>   // your own h2 parser (e.g. lib/h2/frame.js + lib/h2/hpack.js).
> })
> tls.connect()
> ```

---

## Certificate validation

By default (`verifyTLS: true`), hellojs validates the server's certificate chain
on every handshake — both TLS 1.3 and TLS 1.2. A request to a host whose cert
doesn't chain to a trusted root, doesn't match the hostname, or is outside its
validity window will be rejected with `ETLS_CERT_VERIFY` *before any application
data is sent*.

```js
// Default — chain is validated, hostname must match, must terminate in
// Node's bundled root CAs (tls.rootCertificates). MITM proxies are rejected.
await request({ url: 'https://api.example.com/' })

// Opt out — handshake completes regardless of cert validity. Useful for
// self-signed dev servers or when you've wired your own validation elsewhere.
// Treat this as analogous to curl -k / NODE_TLS_REJECT_UNAUTHORIZED=0.
await request({ url: 'https://localhost:8443/', verifyTLS: false })
```

### What's checked

For each cert in the chain (leaf → intermediates → trusted root):

- Validity window — `Date.now()` is within `notBefore` / `notAfter`
- `cert[i].issuer === cert[i+1].subject` — chain doesn't break
- `cert[i].verify(cert[i+1].publicKey)` — signature against the next cert's pubkey

On the leaf specifically:

- Hostname match against `SubjectAltName` per RFC 6125, including wildcard
  support (`*.example.com` matches `foo.example.com`, not `example.com` or
  `foo.bar.example.com`). **CN-only matching is rejected** (deprecated by
  Chrome since v58, 2017).

Chain must terminate either in a self-signed root present in Node's bundled
`tls.rootCertificates`, or in a cert whose issuer matches one of the bundled
roots' subjects and whose signature verifies against that root's pubkey.

On TLS 1.2, the server's `ServerKeyExchange` signature is *additionally* verified
against the leaf cert's public key — this authenticates the ECDHE parameters
themselves, not just the cert chain. (TLS 1.3 has equivalent built-in via
`CertificateVerify`.)

### OCSP stapling

When a server staples its OCSP response (RFC 6066 §8 `CertificateStatus`), hellojs
parses the response, verifies the responder's signature against the issuer cert (or
an embedded delegated responder), and:

- Hard-fails the handshake if any cert in the response is `revoked`
- Soft-fails (logs + continues, matching Chrome's policy) if the signature can't
  be verified — callers wanting hard-fail can inspect `tls.ocsp.signatureVerified`

### Certificate Transparency

We extract Signed Certificate Timestamps (SCTs) from the leaf cert's
`1.3.6.1.4.1.11129.2.4.2` extension and expose them as `result.scts` from
`validateChain()`. Full SCT signature verification requires a CT log key list (not
bundled — distribute via your own update mechanism, then call
`require('@conorre/hellojs/lib/tls/sct').verifySct(sct, leafDer, logKeys)`).

### Errors

When validation fails, the rejection carries `code: 'ETLS_CERT_VERIFY'` (or
`ETLS_HANDSHAKE` for 1.2 SKE-sig mismatches) with a `message` describing exactly
what went wrong:

```
certificate validation failed: leaf cert does not match hostname "evil.com" (subjectAltName=DNS:legit.com)
certificate validation failed: cert[0] expired (notAfter=Mar 15 10:00:00 2025 GMT)
certificate validation failed: chain does not terminate in a trusted root (top issuer="CN=my-corp-ca")
certificate validation failed: OCSP responder reported the leaf as revoked
```

---

## TypeScript

Type declarations ship with the package (`index.d.ts`) and are validated under
`tsc --strict` in CI.

```ts
import request, { HellojsError, HellojsErrorCode, Response, RequestOptions } from '@conorre/hellojs'

const opts: RequestOptions = {
  url: 'https://api.example.com',
  json: true,
  timeouts: { connect: 2000, tlsHandshake: 5000, response: 10_000 },
}

try {
  const res = await request<{ name: string }>({ ...opts, resolveWithFullResponse: true })
  console.log(res.statusCode, res.body.name)
} catch (e) {
  if (e instanceof HellojsError && e.code === 'ETIMEDOUT') { /* retry */ }
}
```

---

## Performance

Benchmarked on macOS / Node 22.11 against a local HTTP/2 server (127.0.0.1, 1 KB
fixed-size response). Each client runs as a fresh subprocess: 1 cold request
(includes TLS handshake), then 30 warm-serial requests on the same connection,
then 50 parallel requests. Reproduce with `node test/bench/clients.js`.

| Client | Cold | Warm p50 | Warm p99 | 50 parallel | RSS Δ |
|---|---:|---:|---:|---:|---:|
| got (h2)         | 9.1 ms  | 0.3 ms   | 1.3 ms   | 6.2 ms       | 9.3 MB |
| node-https (h1)  | 15.6 ms | 0.8 ms   | 1.4 ms   | 21.0 ms      | 15.8 MB |
| node-http2       | 16.3 ms | **0.2 ms** | **0.4 ms** | **2.4 ms** | **7.9 MB** |
| undici (h1)      | 17.3 ms | 0.2 ms   | 0.5 ms   | 26.3 ms      | 11.7 MB |
| axios (h1)       | 17.3 ms | 1.1 ms   | 2.6 ms   | 23.7 ms      | 14.3 MB |
| node-fetch (h1)  | 17.7 ms | 0.9 ms   | 2.1 ms   | 23.8 ms      | 14.2 MB |
| **hellojs**      | **18.9 ms** | **0.3 ms** | **0.7 ms** | **4.6 ms** | **11.8 MB** |

**Where hellojs sits:**

- **Cold connect: 2.6 ms behind node-http2**, within run-to-run noise of every other
  client except got (which is exceptionally fast cold for unclear reasons). The
  remaining gap is the genuine, irreducible cost of (a) building a Chrome-shape
  ClientHello (~1500 B incl. the X25519MLKEM768 hybrid key share) and (b)
  processing the handshake with a pure-JS TLS state machine vs. Node's native
  C++ TLS.
- **Warm p50: tied for fastest** (0.3 ms) with got, node-http2, undici.
- **50 parallel: 2nd fastest** (4.6 ms) — 5-6× faster than every h1 client and
  only 2.2 ms behind raw node-http2. h2 multiplexing wins decisively here.
- **Memory: among the leanest** (11.8 MB RSS Δ); only node-http2 (7.9 MB) and
  got (9.3 MB) are smaller.

None of the alternatives can produce
`JA4 = t13d1516h2_8daaf6152771_d8a2da3f94cd` — that's the trade-off.

### Real-internet (`www.cloudflare.com/cdn-cgi/trace`)

Same harness, different target — measures the cost over a real network path with
genuine TLS handshake RTT. 10 warm + 10 parallel (smaller load to be polite to a
shared endpoint).

| Client | Cold | Warm p50 | Warm p99 | 10 parallel | RSS Δ |
|---|---:|---:|---:|---:|---:|
| axios (h1)       | 82.5 ms  | 23.9 ms | 28.4 ms | 85.6 ms | 9.1 MB |
| node-https (h1)  | 85.4 ms  | 20.8 ms | 22.9 ms | 74.3 ms | 9.9 MB |
| undici (h1)      | 86.9 ms  | 22.0 ms | 23.7 ms | 90.0 ms | 9.4 MB |
| fetch-native     | 93.5 ms  | 21.4 ms | 28.8 ms | 92.6 ms | 29.1 MB |
| node-fetch (h1)  | 95.9 ms  | 24.9 ms | 27.7 ms | 88.0 ms | 10.2 MB |
| node-http2       | 111.0 ms | 22.7 ms | 25.2 ms | **31.4 ms** | 9.4 MB |
| **hellojs**      | 157.1 ms | 25.3 ms | 49.5 ms | **41.9 ms** | 10.8 MB |
| got              | 199.0 ms | 54.1 ms | 62.4 ms | 39.5 ms | 7.9 MB |

**What this shows:**

- **Warm requests are network-bound.** Everyone clusters at 21–25 ms p50 because
  that's the RTT to Cloudflare's edge.
- **Concurrent 10-parallel: hellojs is 2nd-fastest** (41.9 ms), only beaten by
  raw node-http2 (31.4 ms). The h1 clients all pay 74–92 ms because they
  serialize over their pool.
- **Cold connect: hellojs is ~50 ms slower than node-http2** on a real network.
  This is the genuine, irreducible cost of the fingerprint: the larger
  ClientHello (~1500 B vs ~500 B for vanilla Node) takes longer to traverse the
  network, and the pure-JS TLS state machine processes the server's response
  more slowly than Node's native C++ TLS. There's no further optimization
  available here without dropping fingerprint fidelity.

Reproduce: `REMOTE_TARGET=www.cloudflare.com/cdn-cgi/trace node test/bench/clients.js`.

### Soak

`npm run test:soak` runs a sustained-load test against a local h2 server. Current
baseline:

```
200,000 requests in 13s (~15,000 rps)
Heap growth: -5.93 MB (negative — GC reclaimed more than was held)
Active handles after pool.closeAll(): 3
```

Knobs: `SOAK_REQUESTS=1000000 SOAK_CONCURRENCY=200 SOAK_HEAP_BUDGET_MB=128 npm run test:soak`.

---

## Errors

Every operational failure surfaces as a `HellojsError` with a stable
`.code` and `.category`. Use the category for coarse-grained handling
and the code for precise behavior.

```js
const request = require('@conorre/hellojs')

try {
  await request({ url: 'https://example.com/foo' })
} catch (e) {
  if (e instanceof request.HellojsError) {
    console.error(e.code, e.category, e.message)
    if (e.category === 'timeout') { /* retry */ }
    if (e.code === 'ETLS_CERT_VERIFY') { /* refuse to trust */ }
  }
}
```

| Category | Codes | Meaning |
|---|---|---|
| `usage` | `EBADOPTS`, `EBADARG` | Caller passed bad options (programmer error) |
| `transport` | `ECONNREFUSED`, `ECONNRESET`, `ENOTFOUND`, `EPROXY` | TCP / DNS / proxy issues |
| `tls` | `ETLS_ALERT`, `ETLS_HANDSHAKE`, `ETLS_CERT_VERIFY`, `ETLS_VERSION` | Handshake or cert problem |
| `protocol` | `EH2STREAM`, `EH2GOAWAY`, `EH3STREAM`, `EH3CONN`, `EPROTO` | h2 / h3 / QUIC protocol-level failure |
| `http` | `EHTTP`, `EBADRESP`, `EDECOMPRESS` | HTTP status >= 400 (with `simple:true`), parser failure, or content-encoding error |
| `body` | `EBODYSTREAM` | Request body stream errored mid-upload |
| `timeout` | `ETIMEDOUT` | Any phase exceeded its budget — see `timeouts` option |

Retries (when `opts.retry.limit > 0` is set and the method is in
`opts.retry.methods`) automatically retry these codes:
`ETIMEDOUT`, `ECONNRESET`, `EH2STREAM`, `EH3STREAM`, plus any status code
in `opts.retry.statusCodes`.

---

## Debugging

By default the library is silent. Choose a log level via `HELLOJS_LOG`:

```bash
HELLOJS_LOG=error  node my-script.js   # only errors
HELLOJS_LOG=warn   node my-script.js   # + warnings
HELLOJS_LOG=info   node my-script.js   # + notices (handshake summary, etc.)
HELLOJS_LOG=debug  node my-script.js   # + protocol-level detail
HELLOJS_LOG=trace  node my-script.js   # everything (very loud)
```

`HELLOJS_DEBUG=1`, `-d` on argv, and `ENV=development` are all accepted as legacy
aliases for `trace`. You can also set the level from JS:

```js
const log = require('@conorre/hellojs/lib/models/log')
log.setLevel('info')
log.setJsonMode(true)   // emit JSON-line records instead of colored text
```

`HELLOJS_LOG_JSON=1` is the env-var equivalent for JSON-line output (useful for
ingesting into structured-log pipelines).

Sample lines:

```
[tls] [nst] cached ticket: lifetime=64800s nonce=1B ticket=192B maxEarlyData=14336
[tls] [0rtt] server accepted PSK (identity=0)
[tls] [0rtt] sent EndOfEarlyData (earlySeq=1)
[h3] [cc] recovery cwnd=10000 ssthresh=10000 ev=1
[h3] [cid] +seq=2 (pool size=3)
```

### Wireshark decryption

Set `HELLOJS_KEYLOG` to a file path and hellojs will write
SSLKEYLOGFILE-format entries you can load into Wireshark to decrypt
captured TLS sessions:

```bash
HELLOJS_KEYLOG=/tmp/hellojs.keys node my-script.js
```

---

## API surface

```js
const request = require('@conorre/hellojs')

// Main API
request(opts)                    // Promise<body | Response | Readable>
request.get(...)
request.post(...)
request.put(...)
request.del(...)
request.patch(...)
request.head(...)
request.options(...)
request.defaults(defaultOpts)    // bound instance
request.jar()                    // new RFC 6265 cookie jar
request.pool                     // the default connection Pool
request.pool.closeAll()
await request.pool.shutdown(timeoutMs)   // graceful drain
request.HellojsError             // error class
request.observability            // EventEmitter — see Observability hooks

// 0-RTT helper
request.encodeH2EarlyData({ method, path, host, headers })  // Buffer

// Profile registry — clone fingerprints from peet.ws JSON
request.profiles.registerFromPeet(name, peetJson)
request.profiles.register(name, profileObject)
request.profiles.get(name)
request.profiles.list()

// Low-level for advanced use
request.TLS                      // class TLS(host, port, proxy?, opts?)
request.Pool                     // class Pool({ idleTimeoutMs, maxPerHost })

// HTTP/3 stand-alone
const { QuicConnection } = require('@conorre/hellojs/lib/h3/connection')
const { H3Client }       = require('@conorre/hellojs/lib/h3/h3')
```

Errors are `HellojsError` instances. See [Errors](#errors) for the full taxonomy.

---

## Architecture

```
lib/
├── client.js                  request()-shape API (URL parsing, redirects,
│                              cookie jar integration, body codec, retry policy,
│                              streaming response, observability hooks)
├── pool.js                    connection pool — h2 multiplexing + h1 keep-alive,
│                              per-host slot semaphore, graceful drain, happy-eyeballs
├── happy-eyeballs.js          RFC 8305 IPv4/IPv6 race for TCP connect
├── socks5.js                  SOCKS5 client (RFC 1928 + RFC 1929 user/pass)
├── cookies.js                 RFC 6265 cookie jar (Domain/Path/Secure/SameSite/Expires)
├── headers.js                 Chrome 147 default header set + ordering
├── errors.js                  HellojsError + closed-set codes + wrap() promotion
├── observability.js           EventEmitter for request lifecycle
├── h2-earlydata.js            HPACK+h2 frame builder for 0-RTT (encoder only)
├── tls/
│   ├── tls.js                 TLS 1.3 state machine + AEAD + HKDF key schedule
│   ├── tls12.js               TLS 1.2 handshake + 12-suite cipher catalog + EMS
│   ├── tls12_records.js       TLS 1.2 record codec (AEAD GCM/ChaCha20 + CBC)
│   ├── tls12_prf.js           TLS 1.2 PRF (P_SHA256/SHA384) + key schedule
│   ├── cert-validate.js       Chain validation (path + SAN + dates + intermediate trust)
│   ├── ocsp.js                OCSP response parser + signature verifier (RFC 6960)
│   ├── sct.js                 Signed Certificate Timestamp parser (RFC 6962)
│   ├── mlkem.js               X25519MLKEM768 hybrid key exchange + keypair pool
│   └── session-cache.js       NewSessionTicket cache + persistent file (O_EXCL lock)
├── h2/
│   ├── frame.js               9-byte frame header codec + type/flag constants
│   ├── hpack.js               full HPACK (static + dynamic tables, Huffman)
│   └── session.js             H2Session + H2Stream (replaces Node's http2,
│                              with CONTINUATION + per-stream flow control)
├── h3/
│   ├── connection.js          QUIC v1 connection + NewReno + key updates + NCID
│   ├── h3.js                  HTTP/3 layer (control + encoder + decoder streams)
│   ├── packet.js              QUIC packet build/parse + frame codec
│   ├── keys.js                Initial + traffic key derivation + AEAD helpers
│   ├── qpack.js               QPACK static + dynamic-table decode
│   ├── huffman.js             RFC 7541 Huffman encoder + decoder
│   ├── transport-params.js    QUIC transport-parameters TLS extension codec
│   └── varint.js              QUIC variable-length integer codec
├── extensions/
│   └── index.js               every TLS extension builder (profile-driven)
├── profiles/
│   ├── index.js               registry (get/register/registerFromPeet)
│   ├── chrome147-mac.js       canonical Chrome 147 profile
│   └── from-peet.js           paste a tls.peet.ws response → profile object
├── utils/
│   ├── config.js              MESSAGE_TYPES, CIPHERS, HASHES tables
│   └── hkdf.js                HKDF-Extract / Expand / Expand-Label / hashes
└── models/
    └── log.js                 leveled logger (HELLOJS_LOG=info/debug/trace;
                               JSON-line output via HELLOJS_LOG_JSON=1)
```

The custom h2 client (`lib/h2/session.js`) replaces Node's built-in
`http2.connect()` on the hot path. It handles the SETTINGS exchange, HPACK
encode/decode, per-stream and connection flow control, CONTINUATION frame
assembly/emission, frame dispatch, and PING auto-response — vs. the thousands of
lines of internal http2 machinery it bypasses. This is where ~22% of the
cold-connect gains and ~45% of the concurrent-throughput gains came from.

---

## Known limitations

- **ECH:** GREASE-shape only. Real Encrypted Client Hello against published ECHConfigs
  (read from DNS HTTPS records) is not implemented.
- **Certificate Transparency:** SCTs are parsed and exposed; signature verification
  requires a caller-supplied CT log key map. We don't ship the log list.
- **OCSP:** stapled responses are parsed + verified. We don't fetch OCSP responses
  out-of-band when the server doesn't staple.
- **HTTP/2:** Server push not supported (we set `ENABLE_PUSH=0`).
- **HTTP/3:** see [HTTP/3 → What's not implemented](#whats-not-implemented).
  Missing: client-initiated key updates, CUBIC/BBR, QPACK encoder dynamic table, full
  connection migration (socket rebind), 0-RTT-Protected packets.
- **h2 0-RTT response reading through `request()`:** the encoder helper
  (`encodeH2EarlyData`) is exposed and works at the TLS layer, but `request()` itself
  can't return the 0-RTT response — see the [caveat](#h2-0-rtt-encoder-helper) above.
- **Common HTTP features not yet implemented:** WebSocket (`Upgrade: ws`),
  multipart/form-data builder, `Expect: 100-continue`, response Cache-Control/ETag
  semantics, `Retry-After` honoring on 429/503, DNS caching, `Content-Range` resumable
  uploads. These don't affect the fingerprint or TLS layer — they're caller
  conveniences that can sit on top.

---

## License

MIT © Conor Reid
