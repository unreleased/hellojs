// TypeScript declarations for @unreleased/hellojs.
//
// Public surface: a request.js-shape `request()` function plus the lower-level
// `TLS`, `Pool`, and `encodeH2EarlyData` exports.

/// <reference types="node" />

import { EventEmitter } from 'node:events'
import { Duplex } from 'node:stream'

export interface CookieJar {
	getCookieString(host: string): string
	setCookie(setCookieHeader: string | string[], host: string): void
}

/** Body of a `request({ retry: ... })` policy. Field name matches the runtime (lib/client.js). */
export interface RetryPolicy {
	limit?: number
	methods?: string[]
	statusCodes?: number[]
	baseDelayMs?: number
}

export interface PerPhaseTimeouts {
	connect?: number
	tlsHandshake?: number
	response?: number
	idle?: number
}

export interface RequestOptions {
	url?: string
	uri?: string
	method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS' | string
	headers?: Record<string, string | string[]>
	body?: string | Buffer | Uint8Array | NodeJS.ReadableStream | null
	json?: boolean | unknown
	form?: Record<string, string | number>
	qs?: Record<string, string | number | (string | number)[]>
	jar?: CookieJar
	gzip?: boolean
	followRedirect?: boolean
	maxRedirects?: number
	timeout?: number
	timeouts?: PerPhaseTimeouts
	proxy?: string
	forever?: boolean
	h3?: boolean
	resolveWithFullResponse?: boolean
	simple?: boolean
	retry?: RetryPolicy

	/** TLS-only: turn on cert chain validation (default `true`). */
	verifyTLS?: boolean
	/** Opt in to HTTPS/SVCB bootstrap and real ECH on the TCP/QUIC paths. */
	ech?: boolean
	/** TLS 1.3 0-RTT early data to bundle with the PSK. */
	earlyData?: string | Buffer | Uint8Array
	/** When true, resolve as soon as headers arrive and expose the body as a Node Readable. */
	stream?: boolean
}

export interface Response<TBody = unknown> {
	statusCode: number
	status: number
	headers: Record<string, string | string[]>
	body: TBody
	rawBody: Buffer
}

export type HellojsErrorCategory =
	| 'usage' | 'transport' | 'tls' | 'protocol' | 'http' | 'body' | 'timeout'

export type HellojsErrorCode =
	| 'EBADOPTS' | 'EBADARG'
	| 'ECONNREFUSED' | 'ECONNRESET' | 'ENOTFOUND' | 'EPROXY'
	| 'ETLS_ALERT' | 'ETLS_HANDSHAKE' | 'ETLS_CERT_VERIFY' | 'ETLS_VERSION'
	| 'EH2STREAM' | 'EH2GOAWAY' | 'EH3STREAM' | 'EH3CONN' | 'EPROTO'
	| 'EHTTP' | 'EBADRESP' | 'EDECOMPRESS'
	| 'EBODYSTREAM'
	| 'ETIMEDOUT'

export class HellojsError extends Error {
	code: HellojsErrorCode | string
	category: HellojsErrorCategory
	cause?: unknown
	response?: Response
}

export type Callback<TBody = unknown> = (
	err: HellojsError | null,
	res: Response<TBody> | undefined,
	body: TBody | undefined,
) => void

/** Mirrors the runtime export from `lib/profiles/index.js`. Loosely typed because profiles are
 * caller-defined plain objects consumed by lib/tls/tls.js / lib/headers.js / lib/h3/transport-params.js. */
export interface ProfilesRegistry {
	get(name: string): unknown
	list(): string[]
	register(name: string, profile: unknown): unknown
	registerFromPeet(name: string, peetJson: unknown): unknown
	fromPeet(peetJson: unknown): unknown
	profiles: Record<string, unknown>
}

export interface RequestFn {
	<TBody = unknown>(opts: RequestOptions, cb?: Callback<TBody>): Promise<Response<TBody> | TBody>
	(url: string, cb?: Callback): Promise<unknown>
	get<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	post<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	put<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	del<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	delete<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	patch<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	head<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	options<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>

	defaults(defaults: Partial<RequestOptions>): RequestFn
	jar(): CookieJar
	HellojsError: typeof HellojsError
	pool: Pool
	observability: EventEmitter
	profiles: ProfilesRegistry

	/** Exported for advanced users. */
	TLS: typeof TLS
	Pool: typeof Pool
	encodeH2EarlyData: typeof encodeH2EarlyData
}

declare const request: RequestFn
export default request
export = request

export interface TLSOptions {
	verifyTLS?: boolean
	earlyData?: Buffer | Uint8Array
	session?: Buffer
}

export class TLS extends EventEmitter {
	constructor(host: string, port?: number, proxy?: string | null, options?: TLSOptions)
	host: string
	port: number
	alpn: 'h2' | 'http/1.1' | null
	h2Transport: Duplex | null
	h2Session: unknown | null
	server: {
		legacyVersion: number
		sessionId: Buffer
		cipherSuite: number
		selVersion: number | null
		serverKShare?: { group: number; key: Buffer }
	} | null
	connect(): Promise<void>

	on(event: 'ready', listener: () => void): this
	on(event: 'ready-http1', listener: () => void): this
	on(event: 'error', listener: (err: Error) => void): this
}

/** The runtime accepts a single options object (host through sessionIdentity). The older
 * positional signature was removed because the pool now keys connections on additional
 * identity fields (connectHost, tlsName, ech.public_name) that don't fit positional args. */
export class Pool {
	constructor(opts?: { idleTimeoutMs?: number; maxPerHost?: number })
	acquire(opts: {
		host: string
		port?: number
		profile?: string
		proxy?: string
		forceFresh?: boolean
		cacheConnection?: boolean | null
		transport?: 'tcp' | 'quic'
		earlyData?: string | Buffer | Uint8Array | null
		verifyTLS?: boolean
		timeouts?: PerPhaseTimeouts | null
		profileObj?: unknown
		connectHost?: string | null
		tlsName?: string | null
		addressHints?: { v4?: string[]; v6?: string[] } | null
		ech?: unknown
		sessionIdentity?: unknown
	}): Promise<unknown>
	closeAll(): void
	shutdown(timeoutMs?: number): Promise<void>
	readonly idleTimeoutMs: number
}

/** Build an HPACK-encoded HEADERS+DATA blob suitable for embedding in TLS 1.3 0-RTT. */
export function encodeH2EarlyData(req: {
	method: string
	path: string
	host: string
	headers?: Record<string, string>
	body?: Buffer | Uint8Array
}): Buffer
