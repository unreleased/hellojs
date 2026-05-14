// Strict-TS validation of @conorre/hellojs's index.d.ts.
//
// This file is compiled via `tsc --noEmit --strict` in CI. Any drift between the .d.ts
// and the real export shape will surface as a compile error here. Don't import from the
// package name to avoid `node_modules` resolution; use a relative path.

import request, {
	HellojsError,
	HellojsErrorCode,
	HellojsErrorCategory,
	Response,
	RequestOptions,
	TLS,
	Pool,
	PerPhaseTimeouts,
	encodeH2EarlyData,
} from '../../index'
import type { Readable, Writable } from 'node:stream'

async function smoke(): Promise<void> {
	// Basic GET, promise form.
	const body: unknown = await request('https://example.com')

	// Full request opts.
	const r = await request({
		url: 'https://example.com/api',
		method: 'POST',
		headers: { authorization: 'Bearer x' },
		json: { name: 'foo' },
		gzip: true,
		timeout: 5000,
		timeouts: { connect: 1000, tlsHandshake: 2000, response: 3000, idle: 60_000 },
		verifyTLS: true,
		resolveWithFullResponse: true,
	})
	// With resolveWithFullResponse, r is Response<unknown> | unknown — narrow it.
	if (typeof r === 'object' && r !== null && 'statusCode' in r) {
		const res = r as Response
		const code: number = res.statusCode
		const headers: Record<string, string | string[]> = res.headers
		const _b: unknown = res.body
		void code; void headers; void _b
	}

	// Method shortcuts.
	await request.get('https://example.com')
	await request.post({ url: 'https://example.com', json: {} })
	await request.del({ url: 'https://example.com' })

	// Cookie jar.
	const jar = request.jar()
	jar.setCookie('SID=x', 'https://example.com')
	const _ck: string = jar.getCookieString('https://example.com')
	void _ck

	// Error narrowing.
	try {
		await request('https://example.com')
	} catch (e) {
		if (e instanceof HellojsError) {
			const code: HellojsErrorCode | string = e.code
			const cat: HellojsErrorCategory = e.category
			void code; void cat
		}
	}

	// TLS / Pool low-level surface.
	const t = new TLS('example.com', 443, null, { verifyTLS: true })
	t.on('ready', () => {})
	t.on('error', (_err: Error) => {})

	const pool = new Pool({ idleTimeoutMs: 60_000, maxPerHost: 12 })
	void pool

	// 0-RTT helper.
	const blob: Buffer = encodeH2EarlyData({
		method: 'GET',
		path: '/',
		host: 'example.com',
	})
	void blob

	// Streaming response: when stream:true, body is a Readable.
	const stream = await request({ url: 'https://example.com', stream: true }) as Readable
	const sinks: Writable[] = []
	stream.pipe(sinks[0])

	// Streaming request body: Readable as body.
	const streamingReq: RequestOptions = {
		url: 'https://example.com',
		method: 'POST',
		body: process.stdin,   // any Readable
	}
	void streamingReq

	// Per-phase timeouts type.
	const ts: PerPhaseTimeouts = { connect: 1000 }
	void ts

	void body
}

void smoke
