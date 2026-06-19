const net = require('net')
const crypto = require('crypto')
const fs = require('fs')
const { EventEmitter } = require('events')
const { Duplex } = require('stream')
const { H2Session } = require('../h2/session')



const log = require('../models/log')('[tls]')

const HKDF = require('../utils/hkdf')
const {
	CreateStatusRequestExtension,
	CreateSignedCertificateTimestampExtension,
	CreateExtendedMasterSecretExtension,
	CreateCompressCertificateExtension,
	CreateStatusRequestV2Extension,
	CreateSignatureAlgorithmsCertExtension,
	CreateGREASEExtension,
	CreateSNIExtension,
	CreateALPNExtension,
	CreateSupportedGroupsExtension,
	CreateKeyShareX25519,
	CreateKeyShareSingle,
	CreateCookieExtension,
	CreatePreSharedKeyExtension,
	CreateEarlyDataExtension,
	PSK_BINDER_BLOB_LEN,
	CreateSignatureAlgorithmsExtension,
	CreateSupportedVersionsExtension,
	CreatePSKExchangeModesExtension,
	CreateApplicationSettingsExtension,
	CreateEncryptedClientHelloExtension,
	CreateECPointFormatsExtension,
	CreateRenegotationExtension,
	createSessionTicketExtension,
	CreatePaddingExtension,
	pickGreaseTriple,
} = require('../extensions')

const {
	MESSAGE_TYPES,
	CIPHERS,
	HASHES
} = require('../utils/config')

const { acquireMlKemKeyPair, deriveHybridSharedSecret } = require('./mlkem')

const sessionCache = require('./session-cache')

// A duplex that presents *plaintext HTTP/2 bytes* to Node's http2 session.
// Under the hood it uses your TLS app keys to encrypt/decrypt against the raw TCP socket.
class TLSTransport extends Duplex {
  constructor(tls) {
    super()
    this.tls = tls
    this._ended = false
  }

  // Plaintext app bytes -> encrypt with the negotiated record-layer -> write to raw TCP.
  _write(chunk, _enc, cb) {
    try {
      if (!this.tls.handshakeComplete) {
        return cb(new Error('TLS handshake not complete'))
      }
      // TLS 1.2 path encrypts via its own record layer (different cipher/MAC structure).
      if (this.tls.tls12) {
        this.tls.tls12.encryptAppData(chunk)
        return cb()
      }
      const rec = this.tls.encrypt(
        this.tls.clientAppKey,
        this.tls.clientAppIV,
        chunk,
        0x17, // inner content type: application data
        this.tls.clientSeq++
      )
      this.tls.socket.write(rec)
      cb()
    } catch (e) {
      cb(e)
    }
  }

  // Your TLS code will call this.push() with decrypted app data bytes
  _read(_size) {
    // no-op; we push from TLS when data arrives
  }

  // Allow TLS/ALERT to close the readable side cleanly
  endReadable() {
    if (!this._ended) {
      this._ended = true
      this.push(null)
    }
  }

  // Surface a destroy so http2 can tear us down
  _destroy(err, cb) {
    try {
      this.tls.socket?.destroy()
    } finally {
      cb(err)
    }
  }
}

class TLS extends EventEmitter {
	constructor(host, port, proxy, opts = {}) {
		super()

		this.host = host
		this.port = port
		this.proxy = proxy
		// Internal test affordance: when set to 0x0017 / 0x0018, CH1 advertises only that
		// group in supported_groups and sends no real key_share, deterministically forcing
		// any TLS 1.3 server to respond with HRR. Not part of the public API.
		this._forceHRRGroup = opts._forceHRRGroup || null

		// 0-RTT / session resumption (RFC 8446 §4.2.11). opts.session is a NewSessionTicket
		// from sessionCache; if present we offer pre_shared_key + early_data on CH1.
		// opts.earlyData is application bytes to send under the 0-RTT keys; we replay them
		// over 1-RTT if the server rejects (no pre_shared_key echo / no early_data echo in EE).
		this.session = opts.session || null
		// Cert chain validation (RFC 5280 + RFC 6125). DEFAULT ON: the chain must terminate
		// in a Node-bundled trusted root, the leaf must have a SubjectAltName matching the
		// host, every link's signature + validity window must check out. Opt out (e.g. for
		// self-signed dev servers) with { verifyTLS: false }.
		this.verifyTLS = opts.verifyTLS !== false
		this.earlyData = opts.earlyData || null
		this.earlyDataAccepted = null    // null until EncryptedExtensions decides
		this.pskOffered = false
		this.pskAccepted = false

		// Fingerprint profile: drives cipher list, supported_groups, signature_algorithms,
		// ALPN, supported_versions, ALPS, cert compression. Falls back to Chrome 147 defaults
		// if not supplied. Pulled from the global profile registry by name when given a string.
		if (opts.profile) {
			if (typeof opts.profile === 'string') {
				this.profile = require('../profiles').get(opts.profile)
			} else {
				this.profile = opts.profile
			}
		} else {
			this.profile = require('../profiles').get('default')
		}

		this.nextStreamId = 1
		this.socket = null
		this.clientRandom = null
		this.serverRandom = null

		this.buf = Buffer.alloc(0)       // raw TCP bytes
    this.hsBuf = Buffer.alloc(0) 


		this.encHsBuf = Buffer.alloc(0)   // decrypted handshake bytes
    this.appBuf   = Buffer.alloc(0)   // decrypted app bytes (HTTP/2)

		this.cipher = null

		this.transcript = []

		this.serverSeq = 0
		this.clientSeq = 0

		this.handshakeComplete = false
		this.handshakeKeysReady = false   // gates _parseRecords from decrypting before key schedule done

		// MLKEM state (set by connect() before socket open when the profile offers TLS 1.3).
		this.mlkemPk = null
		this.mlkemSk = null

		this.streams = new Map()

		this.h2Transport = null
		this.h2Session = null
	}

	// True when the active profile will ever build a TLS-1.3 hybrid key_share — i.e. it offers
	// TLS 1.3 in supportedVersions (or didn't set the field, which is Chrome-default) AND its
	// extensionOrder either includes id 51 (key_share) or isn't set (legacy Chrome fallback).
	_profileNeedsMlkem() {
		const t = this.profile?.tls || {}
		const versions = t.supportedVersions
		if (Array.isArray(versions) && versions.length && !versions.includes(0x0304)) return false
		if (Array.isArray(t.extensionOrder) && t.extensionOrder.length) {
			return t.extensionOrder.some(e => e && !e.grease && e.id === 51)
		}
		return true   // legacy chrome147-mac path
	}

	onData(chunk) {
		this.buf = Buffer.concat([this.buf, chunk])
		try {
			this._parseRecords()
		} catch (e) {
			this.emit('error', e)
			this.socket?.destroy()
		}
	}

	connect = async () => {
		// MLKEM-768 keypair is only needed for the TLS 1.3 hybrid key_share. Profiles that don't
		// offer TLS 1.3 (supportedVersions omits 0x0304) — TLS-1.2-only parrots, older Java,
		// some middleboxes — pay no MLKEM cost. Default (no supportedVersions) keeps Chrome
		// behaviour: TLS 1.3 + MLKEM.
		const needMlkem = this._profileNeedsMlkem()
		if (needMlkem) {
			const kem = await acquireMlKemKeyPair()
			this.mlkemPk = kem.pk
			this.mlkemSk = kem.sk
		}

		if (this.proxy) {
			const proxyUrl = new URL(this.proxy);
			// SOCKS5: socks5:// or socks5h:// in the proxy URL → use the SOCKS5 client.
			if (proxyUrl.protocol === 'socks5:' || proxyUrl.protocol === 'socks5h:') {
				const { socks5Connect } = require('../socks5')
				socks5Connect({
					proxyHost: proxyUrl.hostname,
					proxyPort: parseInt(proxyUrl.port || 1080, 10),
					username: proxyUrl.username ? decodeURIComponent(proxyUrl.username) : null,
					password: proxyUrl.password ? decodeURIComponent(proxyUrl.password) : null,
					destHost: this.host,
					destPort: this.port,
					connectTimeoutMs: 10_000,
				}).then((sock) => {
					this.socket = sock
					this.socket.on('data', (data) => this.onData(data))
					this.socket.on('close', () => {
						if (this.h2Transport) this.h2Transport.endReadable()
						if (this.h2Session && !this.h2Session.closed) this.h2Session.close()
					})
					this.startClientHello()
				}).catch((err) => this.emit('error', err))
				return
			}
			const proxyOptions = {
				host: proxyUrl.hostname,
				port: proxyUrl.port || 80,
			};

			this.socket = net.createConnection(proxyOptions, () => {
				log.notify(`[socket] connected to proxy ${proxyOptions.host}:${proxyOptions.port}`);

				let connectHeaders = `CONNECT ${this.host}:${this.port} HTTP/1.1\r\nHost: ${this.host}:${this.port}\r\n`;

				if (proxyUrl.username && proxyUrl.password) {
					const auth = 'Basic ' + Buffer.from(`${proxyUrl.username}:${proxyUrl.password}`).toString('base64');
					connectHeaders += `Proxy-Authorization: ${auth}\r\n`;
				}

				connectHeaders += '\r\n';

				this.socket.write(connectHeaders);
			});

			let proxyResponse = '';
			const onProxyData = (data) => {
				proxyResponse += data.toString();
				if (proxyResponse.includes('\r\n\r\n')) {
					const [statusLine] = proxyResponse.split('\r\n');
					if (statusLine.includes('200')) {
						log.notify('[proxy] CONNECT tunnel established');
						this.socket.removeListener('data', onProxyData);
						this.socket.removeAllListeners('error'); // Important to handle proxy connection errors separately
						this.socket.on('data', (data) => this.onData(data));
						this.socket.on('error', (err) => log.error('[socket] error', err));
						this.startClientHello();
					} else {
						this.socket.destroy(new Error(`Proxy connection failed: ${statusLine.trim()}`));
					}
				}
			};

			this.socket.on('data', onProxyData);
			this.socket.on('error', (err) => {
				log.error('[proxy] connection error', err);
				this.socket.destroy();
			});
			this.socket.on('close', () => {
				log.notify('[socket] Connection closed.')
				if (this.h2Transport) this.h2Transport.endReadable()
				if (this.h2Session && !this.h2Session.closed) this.h2Session.close()
			})

		} else {
			// Happy Eyeballs v2 (RFC 8305): race A and AAAA in parallel with a 250ms head
			// start for IPv6. On broken-IPv6 networks this avoids the full SYN timeout.
			const { happyConnect } = require('../happy-eyeballs')
			happyConnect({ host: this.host, port: this.port, connectTimeoutMs: 10_000 })
				.then((sock) => {
					this.socket = sock
					this.socket.on('data', (data) => this.onData(data))
					this.socket.on('close', () => {
						if (this.h2Transport) this.h2Transport.endReadable()
						if (this.h2Session && !this.h2Session.closed) this.h2Session.close()
					})
					this.startClientHello()
				})
				.catch((err) => {
					this.emit('error', err)
				})
		}
	}

	_parseRecords() {
    while (this.buf.length >= 5) {
			const header = this.buf.subarray(0, 5)
			const type   = header[0]
			const recLen = (header[3] << 8) | header[4]

			if (this.buf.length < 5 + recLen) return

			const payload   = this.buf.subarray(5, 5 + recLen)
			const recordBuf = this.buf.subarray(0, 5 + recLen) // exact bytes from the wire
			this.buf = this.buf.subarray(5 + recLen)

      // TLS 1.2 dispatch: once _enterTls12 has installed this.tls12, the TLS12Handshake
      // owns all subsequent records (it handles HANDSHAKE pre-CCS as cleartext, then
      // decrypts under its own key schedule post-CCS, and routes APPLICATION_DATA + ALERT).
      // The very first ServerHello record came through the 1.3 path (which is where the
      // version detection happens), so we ONLY reach the 1.2 branch on subsequent records.
      if (this.tls12) {
        this.tls12.onRecord(type, payload, recordBuf)
        continue
      }

      if (type === MESSAGE_TYPES.HANDSHAKE) {
        this.hsBuf = Buffer.concat([this.hsBuf, payload])
        this._parseHandshakeMessages()
      } else if (type === MESSAGE_TYPES.APPLICATION_DATA) {
				if (!this.handshakeKeysReady && !this.handshakeComplete) {
					// Keys not derived yet (MLKEM decap pending). Re-stash this record into buf and bail; we'll be re-invoked when keys are ready.
					this.buf = Buffer.concat([recordBuf, this.buf])
					return
				}
				this._onEncryptedRecord(recordBuf)
			} else if (type === MESSAGE_TYPES.ALERT) {
				this._handleAlert(payload[0], payload[1], 'cleartext')
			} else if (type === 0x14) {
				// ChangeCipherSpec — TLS 1.3 sends one for middlebox compat; ignore
      } else {
				log.error(`[server] [unknown record type] ${type}`)
      }
    }
  }

	_onEncryptedRecord(record) {
		const key = this.handshakeComplete ? this.serverAppKey : this.serverHandshakeKey
		const iv = this.handshakeComplete ? this.serverAppIV : this.serverHandshakeIV
		const { type, body } = this.decrypt(key, iv, record, this.serverSeq)
		this.serverSeq += 1


		if (type === MESSAGE_TYPES.HANDSHAKE) {
			this.encHsBuf = Buffer.concat([this.encHsBuf, body])
			this._parseDecryptedHandshake()
		} else if (type === MESSAGE_TYPES.APPLICATION_DATA) {
			if (this.handshakeComplete && this.h2Transport) {
				this.h2Transport.push(body)
			} else {
				this.appBuf = Buffer.concat([this.appBuf, body])
			}
		} else if (type === MESSAGE_TYPES.ALERT) {
			this._handleAlert(body[0], body[1], 'encrypted')
		} else {
			log.error(`[server] unknown inner record type: ${type}`)
		}

	}

	// Single home for TLS alert handling. Used by both the cleartext outer-record path
	// and the encrypted inner-record path so that a fatal alert in either always
	// surfaces as an 'error' event with code='ETLSALERT' (was previously swallowed
	// on the inner path, leaving callers to hang until their timeout).
	_handleAlert(level, desc, where) {
		log.error(`[server] [alert ${where}] level=${level} desc=${desc}`)
		if (level === 2) {
			const err = new Error(`TLS fatal alert from server (${where}): level=${level} description=${desc}`)
			err.code = 'ETLSALERT'
			err.alertLevel = level
			err.alertDescription = desc
			this.emit('error', err)
			if (this.h2Transport) this.h2Transport.destroy(err)
			this.socket?.destroy()
		} else {
			// Warning. TLS 1.3 only really uses close_notify (desc=0) and user_canceled (90).
			// End the readable side if h2 is up; otherwise we're mid-handshake — surface as
			// an error rather than letting connect() hang.
			if (this.h2Transport) {
				this.h2Transport.endReadable()
			} else {
				const err = new Error(`TLS warning alert during handshake (${where}): level=${level} description=${desc}`)
				err.code = 'ETLSALERT'
				err.alertLevel = level
				err.alertDescription = desc
				this.emit('error', err)
				this.socket?.destroy()
			}
		}
	}

	_parseHandshakeMessages() {
    while (this.hsBuf.length >= 4) {
      const msgType = this.hsBuf[0]
      const msgLen  = this.hsBuf.readUIntBE(1, 3) // 3-byte BE
      if (this.hsBuf.length < 4 + msgLen) return  // wait for more

      const header = this.hsBuf.subarray(0, 4)
      const body   = this.hsBuf.subarray(4, 4 + msgLen)
      this.hsBuf   = this.hsBuf.subarray(4 + msgLen)

      switch (msgType) {
        case MESSAGE_TYPES.SERVER_HELLO: // ServerHello
          this._parseServerHello(body, Buffer.concat([header, body]))
          break;
        // (you may also see HelloRetryRequest, but it’s encoded as ServerHello — see below)
        default:
          // Some servers may coalesce multiple handshake msgs; if you see others before keys,
          // they’re still plaintext in TLS 1.2 but in 1.3 only ServerHello is plaintext.
          break;
      }
    }
  }

	_parseDecryptedHandshake() {
		while (this.encHsBuf.length >= 4) {
			const msgType = this.encHsBuf[0]
			const msgLen  = this.encHsBuf.readUIntBE(1, 3)
			if (this.encHsBuf.length < 4 + msgLen) return // need more
	
			const body = this.encHsBuf.subarray(4, 4 + msgLen)
			const full = this.encHsBuf.subarray(0, 4 + msgLen)
			this.encHsBuf = this.encHsBuf.subarray(4 + msgLen)

			// keep transcript EXACTLY as bytes
			switch (msgType) {
				case MESSAGE_TYPES.ENCRYPTED_EXTENSIONS:
					this.transcript.push(full)
					this._onEncryptedExtensions(body)
					break;
				case MESSAGE_TYPES.SERVER_CERTIFICATE:
					this.transcript.push(full)
					if (!this._ingestServerCertificate(body)) return
					break;
				case 0x19: // CompressedCertificate (RFC 8879). Sent in place of Certificate when the
					// client advertised compress_certificate. The compressed wire bytes go into the
					// transcript hash (RFC 8879 §5); we decompress to recover and validate the chain.
					this.transcript.push(full)
					if (!this._ingestCompressedCertificate(body)) return
					break;
				case MESSAGE_TYPES.SERVER_CERTIFICATE_VERIFY:
					// Verify BEFORE adding to the transcript: the signature covers the transcript up
					// to and including the Certificate message (RFC 8446 §4.4.3).
					if (!this._verifyCertificateVerify(body)) return
					this.transcript.push(full)
					break;
				case MESSAGE_TYPES.FINISHED:
					this._validateServerFinished(body)
					this.transcript.push(full)
					this._deriveApplicationKeys()
					// RFC 8446 §4.5: if the server accepted our early data, the client MUST send
					// an EndOfEarlyData handshake message (encrypted under the 0-RTT keys) before
					// transitioning to the handshake keys for the Finished message.
					if (this.earlyDataAccepted === true) this._sendEndOfEarlyData()
					this._sendClientFinished()
					break;
				case 0x04: { // NewSessionTicket — post-handshake. Parse + cache the ticket
					// material keyed by host for future session resumption. Actually USING the
					// PSK on a subsequent handshake (with binder + early-data secret derivation)
					// is a separate, larger task — this just captures the data when it arrives.
					try {
						const session = sessionCache.parseNewSessionTicket(body)
						// Also stash the resumption_master_secret-derived PSK so that when we
						// eventually wire CH1's pre_shared_key extension we have what we need.
						// PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
						//                        ticket_nonce, Hash.length)  per RFC 8446 §4.6.1.
						if (this.resumptionMasterSecret) {
							session.psk = HKDF.ExpandLabel(this.resumptionMasterSecret, 'resumption',
								session.ticketNonce, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)
							session.cipher = this.server?.cipherSuite
							session.alpn = this.alpn
						}
						sessionCache.put(this.host, session)
						log.notify(`[nst] cached ticket: lifetime=${session.ticketLifetime}s nonce=${session.ticketNonce.length}B ticket=${session.ticket.length}B maxEarlyData=${session.maxEarlyDataSize}`)
					} catch (e) {
						log.error(`[nst] parse failed: ${e.message}`)
					}
					break;
				}
				default:
					break;
			}
		}
	}

	// Parse + (when verifyTLS) validate the server Certificate message (RFC 8446 §4.4.2). Returns
	// true to continue, or false after emitting an error + destroying the socket.
	_ingestServerCertificate(body) {
		try {
			const { parseCertificateList, validateChain } = require('./cert-validate')
			const certs = parseCertificateList(body)
			this.serverCertChain = certs
			if (this.verifyTLS) {
				const r = validateChain(certs, this.host)
				if (!r.ok) return this._certFail('ECERTVALIDATION', `certificate validation failed: ${r.reason}`)
			}
			return true
		} catch (e) {
			return this._certFail('ECERTPARSE', `Certificate parse failed: ${e.message}`)
		}
	}

	// Decompress + validate a CompressedCertificate message (RFC 8879). Only does work under
	// verifyTLS — the trust decision and CertificateVerify are both gated on it.
	_ingestCompressedCertificate(body) {
		if (!this.verifyTLS) return true
		try {
			const zlib = require('zlib')
			const MAX_CERT_MESSAGE = 262144 // 256 KiB cap on the decompressed message (anti-bomb)
			if (body.length < 8) throw new Error('CompressedCertificate too short')
			const algo = (body[0] << 8) | body[1]
			const uncompLen = (body[2] << 16) | (body[3] << 8) | body[4]
			const compLen = (body[5] << 16) | (body[6] << 8) | body[7]
			if (8 + compLen > body.length) throw new Error('compressed length exceeds message')
			if (uncompLen > MAX_CERT_MESSAGE) throw new Error(`declared cert message too large (${uncompLen})`)
			const comp = body.subarray(8, 8 + compLen)
			let plain
			if (algo === 1) plain = zlib.inflateSync(comp)                  // zlib
			else if (algo === 2) plain = zlib.brotliDecompressSync(comp)    // brotli (Chrome's choice)
			else if (algo === 3) plain = typeof zlib.zstdDecompressSync === 'function'
				? zlib.zstdDecompressSync(comp)
				: Buffer.from(require('fzstd').decompress(comp))            // zstd
			else throw new Error(`unsupported certificate_compression_algorithm ${algo}`)
			if (plain.length !== uncompLen) throw new Error('decompressed length mismatch')
			const { parseCertificateList, validateChain } = require('./cert-validate')
			const certs = parseCertificateList(plain)
			this.serverCertChain = certs
			const r = validateChain(certs, this.host)
			if (!r.ok) return this._certFail('ECERTVALIDATION', `certificate validation failed: ${r.reason}`)
			return true
		} catch (e) {
			return this._certFail('ECERTPARSE', `CompressedCertificate failed: ${e.message}`)
		}
	}

	// Verify the server CertificateVerify signature (RFC 8446 §4.4.3) under verifyTLS.
	_verifyCertificateVerify(body) {
		if (!this.verifyTLS) return true
		try {
			if (!this.serverCertChain || !this.serverCertChain.length) {
				return this._certFail('ECERTVERIFY', 'CertificateVerify with no preceding certificate')
			}
			const scheme = (body[0] << 8) | body[1]
			const sigLen = (body[2] << 8) | body[3]
			const signature = body.subarray(4, 4 + sigLen)
			const transcriptHash = HKDF[this.cipher.hash](...this.transcript)
			const { verifyCertVerify } = require('./cert-validate')
			if (!verifyCertVerify({ scheme, signature, leaf: this.serverCertChain[0], transcriptHash })) {
				return this._certFail('ECERTVERIFY', `CertificateVerify signature invalid (scheme 0x${scheme.toString(16)})`)
			}
			return true
		} catch (e) {
			return this._certFail('ECERTVERIFY', `CertificateVerify failed: ${e.message}`)
		}
	}

	_certFail(code, message) {
		const e = new Error(message)
		e.code = code
		this.emit('error', e)
		this.socket?.destroy()
		return false
	}

	_onEncryptedExtensions(body) {
		// Read ALPN (always) and early_data echo (0x002a — present only when server accepted
		// our 0-RTT). Absence of early_data when we offered it = rejection; the early bytes
		// we sent will be discarded by the server and we need to replay over 1-RTT.
		let p = 0;
		const extTotal = body.readUInt16BE(p); p += 2;
		let end = p + extTotal;

		let sawEarlyData = false
		while (p + 4 <= end) {
			const et = body.readUInt16BE(p); p += 2;
			const el = body.readUInt16BE(p); p += 2;
			const ed = body.subarray(p, p + el); p += el;

			if (et === 0x0010) { // ALPN
				let q = 0;
				const listLen = ed.readUInt16BE(q); q += 2;
				if (listLen > 0) {
					const protoLen = ed[q++];
					this.alpn = ed.subarray(q, q + protoLen).toString('ascii');
				}
			} else if (et === 0x002a) {
				sawEarlyData = true
			}
		}

		if (this.earlyData) {
			this.earlyDataAccepted = sawEarlyData
			log.notify(`[0rtt] server ${sawEarlyData ? 'accepted' : 'rejected'} early data`)
		}
	}

	

	_validateServerFinished(body) {
		// 1. Get a hash of the transcript up to this point (ClientHello...CertificateVerify)
		const transcriptHash = HKDF[this.cipher.hash](...this.transcript)

		// 2. Derive the server's finished key from its handshake traffic secret
		const finishedKey = HKDF.ExpandLabel(this.sHsTraffic, "finished", Buffer.alloc(0), this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		// 3. Compute the expected verify_data using HMAC
		const expectedVerifyData = crypto.createHmac(this.cipher.hash, finishedKey)
			.update(transcriptHash)
			.digest()

		// 4. Validate! Use timingSafeEqual to prevent timing attacks.
		if (!crypto.timingSafeEqual(body, expectedVerifyData)) {
			throw new Error('Server Finished verification failed!')
		}

	}

	_sendClientFinished() {
		// IMPORTANT: The Server Finished message is now part of the transcript for this calculation.
		const transcriptHash = HKDF[this.cipher.hash](...this.transcript)

		// 1. Derive the client's finished key.
		const finishedKey = HKDF.ExpandLabel(this.cHsTraffic, "finished", Buffer.alloc(0), this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		// 2. Compute the verify_data.
		const verifyData = crypto.createHmac(this.cipher.hash, finishedKey)
			.update(transcriptHash)
			.digest()

		const len = Buffer.alloc(3)
		len.writeUIntBE(this.cipher.hashLen, 0, 3)

		// 3. Construct the handshake message for Client Finished.
		const finishedMessage = Buffer.concat([
			Buffer.from([MESSAGE_TYPES.FINISHED]), // Handshake Type: Finished
			len, // Length: 32 bytes
			verifyData
		])

		// 4. Encrypt the message using the CLIENT HANDSHAKE keys.
		// Note: The client's first encrypted message has sequence number 0.
		const encryptedFinished = this.encrypt(
			this.clientHandshakeKey,
			this.clientHandshakeIV,
			finishedMessage,
			MESSAGE_TYPES.HANDSHAKE,
			0     // Sequence number
		)
		// this.clientSeq++; // Increment for the next message (application data)

		this.socket.write(encryptedFinished)

		// Append client Finished to the transcript and derive resumption_master_secret
		// over CH..client_Finished. Any NewSessionTicket arriving post-handshake will use
		// this secret + the ticket nonce to compute its PSK.
		this.transcript.push(finishedMessage)
		const transcriptHashAfter = HKDF[this.cipher.hash](...this.transcript)
		this.resumptionMasterSecret = HKDF.ExpandLabel(this._masterSecret, 'res master', transcriptHashAfter, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		this.handshakeComplete = true

		// Duplex bridge between TLS plaintext bytes and the h2/h1 layer above.
		this.h2Transport = new TLSTransport(this)

		if (this.alpn === 'h2') {
			// Custom minimal H/2 session — replaces Node's http2.connect() on the hot path.
			// It writes the preface + Chrome 147 SETTINGS + WINDOW_UPDATE through our TLS
			// Duplex (which encrypts on the way out), and parses inbound frames from the
			// decrypted byte stream we push.
			this.h2Session = new H2Session(this.h2Transport, this.profile)
			this.h2Session.on('error', (err) => log.error('[h2] session error', err))
			this.h2Session.on('close', () => log.notify('[h2] session closed'))
			this._maybeReplayEarlyData()
			this.emit('ready')
		} else {
			// http/1.1
			this._maybeReplayEarlyData()
			this.emit('ready-http1')
		}
	}

	// RFC 8446 §4.5 / §4.6.1: EndOfEarlyData(5) is an empty-body handshake message sent
	// AFTER the server Finished and BEFORE the client Finished, encrypted under the 0-RTT
	// keys. It tells the server "I'm done with early data; switch to handshake keys." The
	// message becomes part of the transcript so the client Finished MAC covers it.
	_sendEndOfEarlyData() {
		const eoed = Buffer.from([MESSAGE_TYPES.END_OF_EARLY_DATA, 0x00, 0x00, 0x00])
		const prevCipher = this.cipher
		this.cipher = this.earlyCipherInfo
		const rec = this.encrypt(this.clientEarlyKey, this.clientEarlyIV, eoed, MESSAGE_TYPES.HANDSHAKE, this.earlySeq++)
		this.cipher = prevCipher
		this.socket.write(rec)
		this.transcript.push(eoed)
		log.notify(`[0rtt] sent EndOfEarlyData (earlySeq=${this.earlySeq - 1})`)
	}

	// If we sent 0-RTT bytes but the server rejected them (no early_data echo in EE),
	// re-send under the 1-RTT app keys now that the handshake is complete. This is the
	// "replay over 1-RTT" leg of RFC 8446 §4.2.10.
	_maybeReplayEarlyData() {
		if (this._earlyDataBuffered && this.earlyDataAccepted === false) {
			log.notify(`[0rtt] replaying ${this._earlyDataBuffered.length}B over 1-RTT`)
			const rec = this.encrypt(this.clientAppKey, this.clientAppIV, this._earlyDataBuffered, 0x17, this.clientSeq++)
			this.socket.write(rec)
			this._earlyDataBuffered = null
		}
	}

	// Reusable 12-byte nonce scratch buffer + 5-byte header scratch buffer. Sized to fit
	// AES-GCM / ChaCha20-Poly1305 (all use 12-byte nonces). Avoids per-record allocations
	// on the hot encrypt/decrypt path.
	_nonceScratch() {
		return this._nonceBuf || (this._nonceBuf = Buffer.alloc(12))
	}

	// Build TLS 1.3 per-record nonce in place: nonce = iv XOR seq_big_endian (low 8 bytes).
	_writeNonce(iv, seq) {
		const out = this._nonceScratch()
		iv.copy(out, 0, 0, 12)
		// XOR the 64-bit big-endian sequence number into the low 8 bytes.
		// seq is a JS number so up to 2^53 safe.
		const hi = Math.floor(seq / 0x100000000) >>> 0
		const lo = (seq >>> 0)
		out[4]  ^= (hi >>> 24) & 0xff
		out[5]  ^= (hi >>> 16) & 0xff
		out[6]  ^= (hi >>>  8) & 0xff
		out[7]  ^=  hi         & 0xff
		out[8]  ^= (lo >>> 24) & 0xff
		out[9]  ^= (lo >>> 16) & 0xff
		out[10] ^= (lo >>>  8) & 0xff
		out[11] ^=  lo         & 0xff
		return out
	}

	encrypt(key, iv, plaintext, innerType, seq) {
		// payloadLength = plaintext + 1-byte innerType + 16-byte AEAD tag.
		const payloadLength = plaintext.length + 1 + 16

		// 5-byte TLSCiphertext header. New Buffer per call — small (5 bytes), and used both
		// as AAD and as the on-wire header so we'd need to keep both views consistent if we
		// pooled it. Cheap enough to leave alone.
		const header = Buffer.from([
			0x17, 0x03, 0x03,
			(payloadLength >> 8) & 0xff,
			payloadLength & 0xff,
		])

		const nonce = this._writeNonce(iv, seq)
		const cipher = crypto.createCipheriv(this.cipher.aead, key, nonce, { authTagLength: 16 })

		// 4. Set the AAD using the FINALIZED header. This is the critical step.
		cipher.setAAD(header)

		// 5. Encrypt the plaintext and the inner content type.
		const encryptedContent = Buffer.concat([
			cipher.update(plaintext),
			cipher.update(Buffer.from([innerType])),
			cipher.final()
		])

		// 6. Get the authentication tag.
		const authTag = cipher.getAuthTag()

		// 7. The full record is the final header + encrypted content + auth tag.
		return Buffer.concat([header, encryptedContent, authTag])
	}

	decrypt(keyBuf, ivBuf, rec, seq) {
		if (!Buffer.isBuffer(rec)) throw new Error('decrypt(): rec must be a Buffer')
		if (rec.length < 5) throw new Error('decrypt(): record too short')
	
		const header = rec.subarray(0, 5)                   // 5-byte TLSCiphertext header
		const len = (header[3] << 8) | header[4]            // 0x0119 = 281
		const body = rec.subarray(5, 5 + len)             // ciphertext||tag
	
		if (rec.length !== 5 + len) {
			throw new Error(`bad record framing: rec.length=${rec.length}, header.len=${len}`)
		}
		
		// Split tag
		const tag = body.subarray(body.length - 16)
		const ct  = body.subarray(0, body.length - 16)
		
		const nonce = this._writeNonce(ivBuf, seq)
		const dec = crypto.createDecipheriv(this.cipher.aead, keyBuf, nonce, { authTagLength: 16 })
	
		dec.setAAD(header)
		dec.setAuthTag(tag)
		
		const pt = Buffer.concat([dec.update(ct), dec.final()])
		
		// TLS 1.3: last byte is inner content type; strip zero padding before it
		let contentTypeBoundary = pt.length - 1
		while (contentTypeBoundary >= 0 && pt[contentTypeBoundary] === 0x00) {
			contentTypeBoundary--
		}
	
		if (contentTypeBoundary < 0) {
			// This should not happen in a valid record
			throw new Error('Bad record: all zeros in plaintext')
		}
	
		const innerContentType = pt[contentTypeBoundary]
		const inner = pt.subarray(0, contentTypeBoundary)
	
		return {
			type: innerContentType,
			body: inner
		}
	}

	

	_parseServerHello(body, fullMsgBytes) {
		this.transcript.push(fullMsgBytes)

    let o = 0
    const legacyVersion = body.readUInt16BE(o); o += 2;     // expect 0x0303
    const random = body.subarray(o, o + 32); o += 32;

    // Detect HelloRetryRequest (TLS 1.3) — special "random" value
    const HRR_MAGIC = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c','hex')
    const isHRR = HRR_MAGIC.equals(random)

    const sidLen = body[o++] // 1 byte
    const sessionId = body.subarray(o, o + sidLen); o += sidLen

    const cipherSuite = body.readUInt16BE(o); o += 2       // e.g., 0x1301
		// Convert cipher to hex
		const cipherHex = cipherSuite.toString(16)
		this.cipher = HASHES[cipherHex]

    o++  // legacy_compression_method (always 0x00 in TLS 1.3)

    const extTotalLen = body.readUInt16BE(o); o += 2

    // Iterate extensions
    let selVersion = null
    let serverKShare = null
    let hrrSelectedGroup = null
    let hrrCookie = null
    let selAlpn = null
    let serverEMS = false   // server echoed extended_master_secret (RFC 7627)

    let end = o + extTotalLen;
    while (o + 4 <= end) {
      const extType = body.readUInt16BE(o); o += 2
      const extLen  = body.readUInt16BE(o); o += 2
      const extData = body.subarray(o, o + extLen); o += extLen

      if (extType === 0x002b) { // supported_versions (ServerHello / HRR)
        selVersion = extData.readUInt16BE(0) // expect 0x0304
      } else if (extType === 0x0010) { // application_layer_protocol_negotiation (ALPN)
        // u16 list_len | (u8 name_len, name)+ — ServerHello always selects exactly one.
        if (extData.length >= 3) {
          const nameLen = extData[2]
          selAlpn = extData.subarray(3, 3 + nameLen).toString('ascii')
        }
      } else if (extType === 0x0017) { // extended_master_secret (RFC 7627) — empty body
        serverEMS = true
      } else if (extType === 0x0033) { // key_share
        if (isHRR) {
          // HRR key_share is just selected_group (2 bytes), no key
          hrrSelectedGroup = extData.readUInt16BE(0)
        } else {
          const group = extData.readUInt16BE(0)
          const klen  = extData.readUInt16BE(2)
          const key   = extData.subarray(4, 4 + klen)
          serverKShare = { group, key }
        }
      } else if (extType === 0x002c && isHRR) { // cookie (HRR only)
        const cklen = extData.readUInt16BE(0)
        hrrCookie = extData.subarray(2, 2 + cklen)
      } else if (extType === 0x0029 && !isHRR) { // pre_shared_key — server accepted our PSK
        // Body is just the selected_identity (uint16). We only ever offer one identity (index 0).
        if (extData.length >= 2 && this.pskOffered) {
          this.pskAccepted = true
          this.pskSelectedIdentity = extData.readUInt16BE(0)
          log.notify(`[0rtt] server accepted PSK (identity=${this.pskSelectedIdentity})`)
        }
      }
      // ignore others
    }

    if (isHRR) {
      return this._handleHelloRetryRequest(hrrSelectedGroup, hrrCookie)
    }

    // Save fields, then derive shared secret & handshake keys
    this.server = {
      legacyVersion, sessionId, cipherSuite, selVersion, serverKShare,
    }
    if (selAlpn) this.alpn = selAlpn
    this.serverEMS = serverEMS

		// Version dispatch:
		//   supported_versions=0x0304 → TLS 1.3 (existing path).
		//   No supported_versions ext + legacy_version=0x0303 → TLS 1.2.
		//   Anything else (TLS 1.0/1.1, or weird) → reject.
		if (this.server.selVersion === 0x0304) {
			return this._onServerHelloParsed(fullMsgBytes)
		}
		if (this.server.selVersion == null && legacyVersion === 0x0303) {
			return this._enterTls12({ random, sessionId, cipherSuite })
		}
		this.emit('error', new Error(`server picked an unsupported TLS version (legacy=0x${legacyVersion.toString(16)} selected=${this.server.selVersion})`))
		this.socket?.destroy()
  }

	// RFC 8446 §4.1.4: handle HelloRetryRequest. The server is telling us it wants a key_share
	// for a different group than we offered. We must:
	//   1. Replace CH1 in the transcript with a synthetic message_hash record (§4.4.1).
	//   2. Generate a fresh key for the server's selected group.
	//   3. Resend ClientHello (CH2) identical to CH1 except: new key_share, optional cookie.
	_handleHelloRetryRequest(selectedGroup, cookieBytes) {
		log.notify(`[hrr] server demands key_share group=0x${(selectedGroup||0).toString(16)}` + (cookieBytes ? ` cookie=${cookieBytes.length}B` : ''))

		if (selectedGroup == null) {
			const err = new Error('HelloRetryRequest: server did not include a key_share extension')
			err.code = 'EHRR'
			this.emit('error', err); this.socket?.destroy(); return
		}
		if (selectedGroup === 0x11ec || selectedGroup === 0x001d) {
			// We already sent a key_share for both of these; an HRR demanding them is a server bug.
			const err = new Error(`HelloRetryRequest: server requested 0x${selectedGroup.toString(16)} which we already offered`)
			err.code = 'EHRR'
			this.emit('error', err); this.socket?.destroy(); return
		}

		let publicRaw
		try {
			publicRaw = this._generateKeyForGroup(selectedGroup)
		} catch (e) {
			const err = new Error(`HelloRetryRequest: unsupported group 0x${selectedGroup.toString(16)}: ${e.message}`)
			err.code = 'EHRR'
			this.emit('error', err); this.socket?.destroy(); return
		}

		// Transcript reset (§4.4.1): synthetic CH1 = message_hash(0xFE) || uint24(hashLen) || H(CH1).
		const chBytes = this.transcript[0]
		const hrrBytes = this.transcript[1]
		const h = crypto.createHash(this.cipher.hash).update(chBytes).digest()
		const lenBuf = Buffer.alloc(3); lenBuf.writeUIntBE(h.length, 0, 3)
		const synthetic = Buffer.concat([Buffer.from([0xfe]), lenBuf, h])
		this.transcript = [synthetic, hrrBytes]

		const keyShareExt = CreateKeyShareSingle(selectedGroup, publicRaw)
		const cookieExt = cookieBytes ? CreateCookieExtension(cookieBytes) : null
		this.startClientHello({ keyShareExt, cookieExt })
	}

	_generateKeyForGroup(group) {
		if (group === 0x0017) { // secp256r1 (P-256)
			const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
			this.clientPrivateKey = privateKey
			const der = publicKey.export({ type: 'spki', format: 'der' })
			return der.subarray(der.length - 65) // 0x04 || X(32) || Y(32)
		}
		if (group === 0x0018) { // secp384r1 (P-384)
			const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
			this.clientPrivateKey = privateKey
			const der = publicKey.export({ type: 'spki', format: 'der' })
			return der.subarray(der.length - 97) // 0x04 || X(48) || Y(48)
		}
		throw new Error(`group not implemented: 0x${group.toString(16)}`)
	}

	// Enter the TLS 1.2 state machine. From this point onwards records get routed via
	// this.tls12 instead of the 1.3 paths in _parseRecords / _parseDecryptedHandshake.
	_enterTls12({ random, sessionId, cipherSuite }) {
		const { TLS12Handshake } = require('./tls12')
		try {
			this.tls12 = new TLS12Handshake(this, { random, sessionId, cipherSuite })
		} catch (e) {
			this.emit('error', e)
			this.socket?.destroy()
		}
	}

	_onServerHelloParsed() {
		// Now that we know the server picked TLS 1.3, send the dummy ChangeCipherSpec
		// record for middlebox compatibility (RFC 8446 §D.4). We deferred this from
		// startClientHello so that the TLS 1.2 fallback path doesn't get tripped up by
		// a strict-1.2 server interpreting an early CCS as a real protocol event.
		this.socket.write(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]))

		const group = this.server.serverKShare.group
		const serverShareKey = this.server.serverKShare.key

		const finishKeyDerivation = (shared) => {
			// Hash the whole transcript: [CH, SH] on the standard path, or
			// [synthetic_CH1, HRR, CH2, SH] when an HRR happened. Both produce the
			// correct ClientHello…ServerHello transcript hash for handshake_secret derivation.
			const thSH = HKDF[this.cipher.hash](...this.transcript)
			this._completeHandshakeKeySchedule(shared, thSH)
		}

		if (group === 0x001d) {
			// X25519
			const myPubDer = crypto.createPublicKey(this.clientPrivateKey).export({type:'spki', format:'der'})
			const myPubRaw = myPubDer.subarray(myPubDer.length - 32)
			if (!myPubRaw.equals(this.clientPubRaw32)) {
				throw new Error('X25519 mismatch: privateKey does not match the public sent in ClientHello')
			}
			const serverSpki = rawX25519ToSpkiDer(serverShareKey)
			const serverPub  = crypto.createPublicKey({ type: 'spki', format: 'der', key: serverSpki })
			const shared = crypto.diffieHellman({ publicKey: serverPub, privateKey: this.clientPrivateKey })
			finishKeyDerivation(shared)
		} else if (group === 0x11ec) {
			// X25519MLKEM768 — async (decap)
			deriveHybridSharedSecret(serverShareKey, this.mlkemSk, this.clientPrivateKey).then(shared => {
				finishKeyDerivation(shared)
				this._parseRecords()  // re-drive any records that arrived while we awaited
			}, err => {
				log.error(`[mlkem] decap failed: ${err.message}`)
				this.emit('error', err)
				this.socket?.destroy()
			})
		} else if (group === 0x0017 || group === 0x0018) {
			// secp256r1 / secp384r1 — used on the HRR fallback path. Server's share is the
			// uncompressed point (0x04 || X || Y). Node's diffieHellman returns the shared X.
			const curve = group === 0x0017 ? 'prime256v1' : 'secp384r1'
			const expectedLen = group === 0x0017 ? 65 : 97
			if (serverShareKey.length !== expectedLen || serverShareKey[0] !== 0x04) {
				const err = new Error(`bad ECDHE server share for 0x${group.toString(16)}: len=${serverShareKey.length}`)
				this.emit('error', err); this.socket?.destroy(); return
			}
			const ecdh = crypto.createECDH(curve)
			// Set our private from the privateKey JWK 'd' (raw scalar).
			const jwk = this.clientPrivateKey.export({ format: 'jwk' })
			const d = Buffer.from(jwk.d, 'base64url')
			ecdh.setPrivateKey(d)
			const shared = ecdh.computeSecret(serverShareKey)
			finishKeyDerivation(shared)
		} else {
			const err = new Error(`Unsupported key_share group from server: 0x${group.toString(16)}`)
			this.emit('error', err)
			this.socket?.destroy()
			return
		}
	}

	_completeHandshakeKeySchedule(shared, thSH) {

		const zeros = Buffer.alloc(this.cipher.hashLen, 0x00)
		// When the server accepted our PSK, early_secret was derived from the PSK rather than
		// from zeros. Everything downstream (derived0 → handshake_secret) chains off of that.
		const earlySecret = this.pskAccepted
			? this.pskEarlySecret
			: HKDF.Extract(this.cipher.hash, zeros, zeros)

		// sha256(''), not an empty buffer/str
		const emptyHash = crypto.createHash(this.cipher.hash).update(Buffer.alloc(0)).digest()

		// derived_secret0 = Expand-Label(early_secret, "derived", "", HashLen)
		const derived0 = HKDF.ExpandLabel(earlySecret, "derived", emptyHash, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		// handshake_secret = HKDF-Extract(derived0, shared_secret)
		this.handshakeSecret = HKDF.Extract(this.cipher.hash, derived0, shared)

		// Traffic secrets
		this.sHsTraffic = HKDF.ExpandLabel(this.handshakeSecret, "s hs traffic", thSH, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)
		this.cHsTraffic = HKDF.ExpandLabel(this.handshakeSecret, "c hs traffic", thSH, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		// Finally: keys & IVs for the handshake phase
		this.serverHandshakeKey = HKDF.ExpandLabel(this.sHsTraffic, "key", Buffer.alloc(0), this.cipher.keyLen, this.cipher.hash, this.cipher.hashLen)
		this.serverHandshakeIV  = HKDF.ExpandLabel(this.sHsTraffic, "iv",  Buffer.alloc(0), this.cipher.ivLen, this.cipher.hash, this.cipher.hashLen)

		// (For completeness, the client side too)
		this.clientHandshakeKey = HKDF.ExpandLabel(this.cHsTraffic, "key", Buffer.alloc(0), this.cipher.keyLen, this.cipher.hash, this.cipher.hashLen)
		this.clientHandshakeIV  = HKDF.ExpandLabel(this.cHsTraffic, "iv",  Buffer.alloc(0), this.cipher.ivLen, this.cipher.hash, this.cipher.hashLen)

		if (process.env.HELLOJS_KEYLOG) {
			const keylogPath = process.env.HELLOJS_KEYLOG
			writeKeyLogLine(keylogPath, 'CLIENT_HANDSHAKE_TRAFFIC_SECRET', this.clientRandom, this.cHsTraffic)
			writeKeyLogLine(keylogPath, 'SERVER_HANDSHAKE_TRAFFIC_SECRET', this.clientRandom, this.sHsTraffic)
		}

		this.handshakeKeysReady = true
	}

	_deriveApplicationKeys() {
		// 1. Get the hash of the full handshake transcript up to this point.
		const transcriptHash = HKDF[this.cipher.hash](...this.transcript)

		// 2. Derive the master secret from the handshake secret.
		const emptyHash = crypto.createHash(this.cipher.hash).update(Buffer.alloc(0)).digest()
		const derivedSecret = HKDF.ExpandLabel(this.handshakeSecret, "derived", emptyHash, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)
		const masterSecret = HKDF.Extract(this.cipher.hash, derivedSecret, Buffer.alloc(this.cipher.hashLen, 0x00))

		// 3. Derive client and server application traffic secrets.
		const cAppTraffic = HKDF.ExpandLabel(masterSecret, "c ap traffic", transcriptHash, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)
		const sAppTraffic = HKDF.ExpandLabel(masterSecret, "s ap traffic", transcriptHash, this.cipher.hashLen, this.cipher.hash, this.cipher.hashLen)

		// Stash master_secret so we can derive resumption_master_secret AFTER pushing the
		// client Finished into the transcript (resumption_master_secret = Derive-Secret(
		// master_secret, "res master", ClientHello..client_Finished) per RFC 8446 §7.1).
		this._masterSecret = masterSecret

		// 4. Derive the final keys and IVs for application data.
		this.clientAppKey = HKDF.ExpandLabel(cAppTraffic, "key", Buffer.alloc(0), this.cipher.keyLen, this.cipher.hash, this.cipher.hashLen)
		this.clientAppIV  = HKDF.ExpandLabel(cAppTraffic, "iv",  Buffer.alloc(0), this.cipher.ivLen, this.cipher.hash, this.cipher.hashLen)
		this.serverAppKey = HKDF.ExpandLabel(sAppTraffic, "key", Buffer.alloc(0), this.cipher.keyLen, this.cipher.hash, this.cipher.hashLen)
		this.serverAppIV  = HKDF.ExpandLabel(sAppTraffic, "iv",  Buffer.alloc(0), this.cipher.ivLen, this.cipher.hash, this.cipher.hashLen)


		// Reset sequence numbers for the application data phase
		this.clientSeq = 0
		this.serverSeq = 0
	}

	startClientHello = (hrrCtx = null) => {
		// Construct the record header for the clientHello
		// We don't know the lengths yet so we leave them out until the end
		// 0x16: Handshake
		// 0x03 0x01: TLS 1.3
		const recordHeader = Buffer.from([
			MESSAGE_TYPES.HANDSHAKE,
			0x03, 0x01
		])

		// 0x01: ClientHello
		const handshakeHeader = Buffer.from([MESSAGE_TYPES.CLIENT_HELLO])

		// 0x03 0x03: TLS1.2 (But used for TLS1.3 too for legacy support)
		const legacyVersion = Buffer.from([0x03, 0x03])

		// On HRR retransmit, RFC 8446 §4.1.2 requires CH2 to be identical to CH1 except for the
		// allowed changes (key_share, optional cookie). Reuse the saved clientRandom, sessionId,
		// and GREASE values from CH1 so everything else stays bit-identical.
		if (!hrrCtx) {
			this.clientRandom = crypto.randomBytes(32)
			this._sessionId = crypto.randomBytes(32)
			this._grease = pickGreaseTriple()
		}
		const sessionId = this._sessionId
		const sessionIdLength = Buffer.from([sessionId.length])
		const grease = this._grease

		// Cipher list. Driven by the active fingerprint profile so a parrot'd Chrome 148/etc
		// can reorder/swap ciphers without touching this file. Profile MUST be set by the
		// constructor. useGrease=false (set by fromPeet when the input had zero GREASE) skips
		// every GREASE-injection site — required to round-trip non-Chrome / TLS-1.2-only parrots.
		const useGrease = this.profile.tls.useGrease !== false
		const profileCiphers = this.profile.tls.ciphers
		const cipherList = useGrease ? [(grease.a << 8) | grease.a, ...profileCiphers] : [...profileCiphers]
		const cipherSuites = Buffer.alloc(cipherList.length * 2)
		cipherList.forEach((id, i) => cipherSuites.writeUInt16BE(id, i * 2))

		const cipherSuitesLength = Buffer.alloc(2)
		cipherSuitesLength.writeUInt16BE(cipherSuites.length, 0)

		const compression = Buffer.from([0x01, 0x00])

		let keyShareExtension = null
		if (hrrCtx) {
			// CH2 after HRR — single key_share for server-requested group; the new private key
			// was generated by _handleHelloRetryRequest and lives on this.clientPrivateKey.
			keyShareExtension = hrrCtx.keyShareExt
		} else if (this._profileNeedsMlkem()) {
			// TLS-1.2-only profiles skip key_share construction entirely (saves an X25519 keygen
			// plus the MLKEM concat). EXT_BUILDERS[51] will never be invoked because id 51 won't
			// be in middleIds for those profiles.
			const keyShare = CreateKeyShareX25519(grease.c, this.mlkemPk, { useGrease })
			this.clientPrivateKey = keyShare.privateKey
			this.clientPubRaw32 = keyShare.publicRaw32
			keyShareExtension = keyShare.extension
		}

		// Build all the extensions, driven by the fingerprint profile.
		const ptls = this.profile.tls

		// Builders keyed by IANA extension ID. Each is a thunk so we only materialize the
		// extensions a profile actually lists. Profiles that don't set extensionOrder fall
		// back to the legacy "every Chrome 147 extension" set defined below.
		const EXT_BUILDERS = {
			0:     () => CreateSNIExtension(this.host),                                                             // server_name
			5:     () => CreateStatusRequestExtension(ptls.statusRequest),                                          // status_request
			10:    () => CreateSupportedGroupsExtension(grease.c, ptls.supportedGroups, { useGrease }),            // supported_groups
			11:    () => CreateECPointFormatsExtension(),                                                           // ec_point_formats
			13:    () => CreateSignatureAlgorithmsExtension(ptls.signatureAlgorithms),                              // signature_algorithms
			16:    () => CreateALPNExtension(ptls.alpn || ['h2', 'http/1.1']),                                       // alpn
			17:    () => CreateStatusRequestV2Extension(ptls.statusRequestV2),                                       // status_request_v2 (RFC 6961)
			18:    () => CreateSignedCertificateTimestampExtension(),                                               // signed_certificate_timestamp
			21:    () => CreatePaddingExtension(ptls.paddingLength ?? 0),                                            // padding
			23:    () => CreateExtendedMasterSecretExtension(),                                                     // extended_master_secret
			27:    () => CreateCompressCertificateExtension(ptls.certCompressionAlgorithms),                         // compress_certificate
			35:    () => createSessionTicketExtension(),                                                            // session_ticket
			43:    () => CreateSupportedVersionsExtension(grease.b, ptls.supportedVersions, { useGrease }),         // supported_versions
			45:    () => CreatePSKExchangeModesExtension(),                                                         // psk_key_exchange_modes
			50:    () => CreateSignatureAlgorithmsCertExtension(                                                    // signature_algorithms_cert
				ptls.signatureAlgorithmsCertRaw ? { raw: ptls.signatureAlgorithmsCertRaw } :
				ptls.signatureAlgorithmsCert     ? { sigalgs: ptls.signatureAlgorithmsCert } :
				                                   { sigalgs: ptls.signatureAlgorithms || [] }),
			51:    () => keyShareExtension,                                                                          // key_share
			17613: () => CreateApplicationSettingsExtension(ptls.alpsProtocols, ptls.alpsExtensionType || 0x44cd),   // ALPS v1
			17517: () => CreateApplicationSettingsExtension(ptls.alpsProtocols, ptls.alpsExtensionType || 0x446d),   // ALPS v2
			65037: () => CreateEncryptedClientHelloExtension(),                                                     // ECH GREASE
			65281: () => CreateRenegotationExtension(),                                                             // renegotiation_info
		}

		// Compute which extension IDs the profile wants in the middle block. If
		// profile.tls.extensionOrder is present, it's authoritative: GREASE markers are dropped
		// (we add our own boundary GREASEs). Unknown IDs warn loudly — silent drops corrupt the
		// fingerprint without explanation and have to be discovered by diffing wire captures.
		// Profiles can set tls.strictExtensions=true to throw instead.
		const LEGACY_CHROME_IDS = [13, 27, 43, 51, 10, 16, 0, 23, 18, 5, 45, 17613, 65037, 11, 35, 65281]
		let middleIds
		if (Array.isArray(ptls.extensionOrder) && ptls.extensionOrder.length) {
			middleIds = []
			for (const e of ptls.extensionOrder) {
				if (!e || e.grease) continue
				if (EXT_BUILDERS[e.id] != null) {
					middleIds.push(e.id)
				} else {
					const msg = `extensionOrder includes id ${e.id} (0x${e.id.toString(16)}) but no builder is registered — fingerprint will not match`
					if (ptls.strictExtensions) throw new Error(`tls: ${msg}`)
					log.notify(`[ext] WARN ${msg}`)
				}
			}
		} else {
			middleIds = LEGACY_CHROME_IDS.slice()
		}

		const namedExts = {}
		for (const id of middleIds) namedExts[String(id)] = EXT_BUILDERS[id]()

		// Add cookie ext on CH2 if HRR provided one (RFC 8446 §4.2.2 — verbatim echo).
		if (hrrCtx && hrrCtx.cookieExt) {
			namedExts.cookie = hrrCtx.cookieExt
		}

		// 0-RTT setup: if we have a cached session, prepare PSK extension to append after
		// the trailing GREASE (RFC 8446 §4.2.11 — "MUST be the last extension"). The
		// early_data extension goes into the shuffled middle alongside the others.
		let pskCtx = null
		if (this.session && this.session.psk && !hrrCtx) {
			const cipherInfo = HASHES[this.session.cipher.toString(16)]
			if (cipherInfo) {
				const binderLen = cipherInfo.hashLen
				const ticketAge = (Date.now() - this.session.issuedAt + this.session.ticketAgeAdd) >>> 0
				pskCtx = {
					ext: CreatePreSharedKeyExtension(this.session.ticket, ticketAge, binderLen),
					binderLen,
					hashName: cipherInfo.hash,
					hashLen: cipherInfo.hashLen,
					cipherInfo,
				}
				this.pskOffered = true
				if (this.earlyData) {
					namedExts.early_data = CreateEarlyDataExtension()
				}
			}
		}

		// Test affordance: force an HRR. CH1 advertises supported_groups=[GREASE,P-256,P-384]
		// and sends an empty key_share — server MUST HRR demanding P-256. CH2 must keep the
		// same supported_groups (RFC 8446 §4.1.2 forbids changing it).
		if (this._forceHRRGroup) {
			namedExts.supported_groups = (() => {
				const groups = Buffer.concat([
					Buffer.from([grease.c, grease.c]),
					Buffer.from([0x00, 0x17]),  // P-256
					Buffer.from([0x00, 0x18]),  // P-384
				])
				const groupsLen = Buffer.alloc(2); groupsLen.writeUInt16BE(groups.length, 0)
				const extLen = Buffer.alloc(2); extLen.writeUInt16BE(groups.length + 2, 0)
				return Buffer.concat([Buffer.from([0x00, 0x0a]), extLen, groupsLen, groups])
			})()
			if (!hrrCtx) {
				// Empty client_shares on CH1; CH2 carries the real single entry via hrrCtx.
				namedExts.key_share = (() => {
					const sharesLen = Buffer.alloc(2); sharesLen.writeUInt16BE(0, 0)
					const extLen = Buffer.alloc(2); extLen.writeUInt16BE(2, 0)
					return Buffer.concat([Buffer.from([0x00, 0x33]), extLen, sharesLen])
				})()
			}
		}

		// Extension order policy. Default for Chrome-shaped profiles: shuffle per-instance
		// (matches Chrome's behaviour). For parrots sourced from a single capture (e.g. fromPeet
		// when useGrease=false), preserve the captured wire order so JA3/JA4 reproduce. Profiles
		// can override via tls.extensionPermutation: 'shuffle-middle' | 'preserve'.
		// If PSK is being offered, append it AFTER the trailing GREASE (RFC 8446 §4.2.11
		// requires PSK to be the absolute last extension).
		const middleNames = Object.keys(namedExts)
		const policy = ptls.extensionPermutation || (useGrease ? 'shuffle-middle' : 'preserve')
		if (policy === 'shuffle-middle') {
			const seed = this.clientRandom.readUInt32BE(0)
			shuffleSeeded(middleNames, seed)
		} else if (policy === 'preserve' && Array.isArray(ptls.extensionOrder) && ptls.extensionOrder.length) {
			// Reorder middleNames to match profile.extensionOrder (skipping GREASE markers and
			// any ids we couldn't build). Anything not in the captured order (e.g. cookie/PSK
			// added later) stays at its current position.
			const wireOrder = ptls.extensionOrder.filter(e => e && !e.grease && namedExts[String(e.id)] != null).map(e => String(e.id))
			const extras = middleNames.filter(n => !wireOrder.includes(n))
			middleNames.length = 0
			middleNames.push(...wireOrder, ...extras)
		}
		const extPieces = []
		if (useGrease) extPieces.push(CreateGREASEExtension(grease.a))
		for (const n of middleNames) extPieces.push(namedExts[n])
		if (useGrease) extPieces.push(CreateGREASEExtension(grease.b))
		if (pskCtx) extPieces.push(pskCtx.ext)
		const extensionsList = Buffer.concat(extPieces)

		const extensionsLen = Buffer.alloc(2)
		extensionsLen.writeUInt16BE(extensionsList.length, 0)

		const clientHelloBody = Buffer.concat([
			legacyVersion,            // 2
			this.clientRandom,        // 32
			sessionIdLength,          // 1
			sessionId,                // 32
			cipherSuitesLength,       // 2
			cipherSuites,             // 2
			compression,              // 2 (00 count + 00 method) -> actually 1+1
			extensionsLen,            // 2
			extensionsList,           // variable
		])

		const hsLen = Buffer.alloc(3)
		hsLen.writeUIntBE(clientHelloBody.length, 0, 3) // uint24 BE

		const handshakeMsg = Buffer.concat([
			handshakeHeader, // 0x01
			hsLen,         // uint24 length
			clientHelloBody,
		])

		// Compute and patch the PSK binder if we offered PSK. The binder is HMAC over the
		// transcript hash of CH1 with the binders truncated off. We left binder bytes as
		// zeros when building pskCtx.ext, so the byte offsets are known. Sequence:
		//   1) early_secret = HKDF-Extract(zeros, psk)
		//   2) binder_key   = HKDF-Expand-Label(early_secret, "res binder", H(""), L)
		//   3) finished_key = HKDF-Expand-Label(binder_key, "finished", "", L)
		//   4) binder       = HMAC(finished_key, H(handshakeMsg_truncated))
		//   5) patch binder into handshakeMsg at offset (length - binderLen)
		if (pskCtx) {
			const bindersBlobLen = PSK_BINDER_BLOB_LEN(pskCtx.binderLen)
			const truncated = handshakeMsg.subarray(0, handshakeMsg.length - bindersBlobLen)
			const thTrunc = crypto.createHash(pskCtx.hashName).update(truncated).digest()

			const zeros = Buffer.alloc(pskCtx.hashLen, 0)
			const earlySecret = HKDF.Extract(pskCtx.hashName, zeros, this.session.psk)
			const emptyHash = crypto.createHash(pskCtx.hashName).update(Buffer.alloc(0)).digest()
			const binderKey = HKDF.ExpandLabel(earlySecret, 'res binder', emptyHash, pskCtx.hashLen, pskCtx.hashName, pskCtx.hashLen)
			const finishedKey = HKDF.ExpandLabel(binderKey, 'finished', Buffer.alloc(0), pskCtx.hashLen, pskCtx.hashName, pskCtx.hashLen)
			const binder = crypto.createHmac(pskCtx.hashName, finishedKey).update(thTrunc).digest()
			binder.copy(handshakeMsg, handshakeMsg.length - pskCtx.binderLen)

			// Stash for later: handshake_secret derivation uses early_secret (not zeros-extract).
			this.pskEarlySecret = earlySecret
			this.pskHashName = pskCtx.hashName
			this.pskHashLen = pskCtx.hashLen

			// Derive client_early_traffic_secret using transcript-hash of the FULL CH (with
			// the binder patched in). Used to encrypt 0-RTT app data records.
			const thFull = crypto.createHash(pskCtx.hashName).update(handshakeMsg).digest()
			const cetSecret = HKDF.ExpandLabel(earlySecret, 'c e traffic', thFull, pskCtx.hashLen, pskCtx.hashName, pskCtx.hashLen)
			this.clientEarlyKey = HKDF.ExpandLabel(cetSecret, 'key', Buffer.alloc(0), pskCtx.cipherInfo.keyLen, pskCtx.hashName, pskCtx.hashLen)
			this.clientEarlyIV  = HKDF.ExpandLabel(cetSecret, 'iv',  Buffer.alloc(0), pskCtx.cipherInfo.ivLen, pskCtx.hashName, pskCtx.hashLen)
			this.earlyCipherInfo = pskCtx.cipherInfo
			this.earlySeq = 0
		}

		this.transcript.push(handshakeMsg)

		// ---- Record header: type(1) + legacy_version(2) + length(2)
		const recLen = Buffer.alloc(2)
		recLen.writeUInt16BE(handshakeMsg.length, 0)
	
		const record = Buffer.concat([
			recordHeader,
			recLen,
			handshakeMsg,
		])

		// The TLS 1.3 middlebox-compat dummy CCS (RFC 8446 §D.4) used to be appended here
		// and sent in the same flight as ClientHello. That breaks TLS 1.2 fallback: a
		// strict TLS 1.2 server interprets the early CCS as a real protocol-level CCS
		// before keys are derived and emits unexpected_message on our subsequent CKE.
		// Solution: defer the dummy CCS until we know which version the server picked.
		// _onServerHelloParsed sends it when version == TLS 1.3. The 1.2 path sends CCS
		// as part of the proper CKE → CCS → Finished flight in tls12.js.
		const pieces = [record]

		// 0-RTT app data — encrypt under client_early_traffic_secret and bundle into the
		// same flight as the ClientHello. Buffered for replay if the server rejects.
		if (pskCtx && this.earlyData && this.earlyData.length > 0) {
			const prevCipher = this.cipher
			this.cipher = pskCtx.cipherInfo
			const rec = this.encrypt(this.clientEarlyKey, this.clientEarlyIV, this.earlyData, 0x17, this.earlySeq++)
			this.cipher = prevCipher
			pieces.push(rec)
			this._earlyDataBuffered = this.earlyData
			log.notify(`[0rtt] sent ${this.earlyData.length}B early data (cipher=0x${this.session.cipher.toString(16)})`)
		}

		// Observability: record the JA3 + JA4 of the CH we're putting on the wire so callers
		// can diff against profile.expected.* without needing tls.peet.ws. parseClientHello /
		// ja3 / ja4 are pure functions of the CH bytes — no I/O. We compute on CH1 (no hrrCtx)
		// because hashes are conventionally taken from the first hello.
		if (!hrrCtx) {
			try {
				const { parseClientHello, ja3, ja4 } = require('./fingerprint')
				const parsed = parseClientHello(record)
				const j3 = ja3(parsed)
				const j4 = ja4(parsed)
				this.actualFingerprint = { ja3: j3.hash, ja3_str: j3.str, ja4: j4.str }
				this.emit('fingerprint', this.actualFingerprint)
			} catch (e) {
				log.notify(`[fp] WARN could not derive ja3/ja4 from CH: ${e.message}`)
			}
		}

		this.socket.write(Buffer.concat(pieces))
	}
}


const rawX25519ToSpkiDer = (raw32) => {
	const hdr = Buffer.from('302a300506032b656e032100', 'hex') // X25519 SPKI header
	return Buffer.concat([hdr, raw32])
}

// Deterministic shuffle (mulberry32) used to permute extension order per TLS instance.
// Same seed yields same order, so a single TLS instance always emits identical bytes
// for retransmits while different instances see fresh orders — matches Chrome's
// per-process extension permutation behavior.
function shuffleSeeded(arr, seed) {
	let s = seed >>> 0
	const rand = () => {
		s = (s + 0x6D2B79F5) >>> 0
		let t = s
		t = Math.imul(t ^ (t >>> 15), t | 1)
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296
	}
	for (let i = arr.length - 1; i > 0; i--) {
		const j = Math.floor(rand() * (i + 1))
		;[arr[i], arr[j]] = [arr[j], arr[i]]
	}
	return arr
}



function writeKeyLogLine(path, label, clientRandomBuf, secretBuf) {
	const line = `${label} ${clientRandomBuf.toString('hex')} ${secretBuf.toString('hex')}\n`
	fs.appendFileSync(path, line)
}

module.exports = { TLS, TLSTransport }
