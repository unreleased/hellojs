// QUIC transport parameters TLS extension (id 0x39).
//
// Each parameter is a varint-tagged TLV: { param_id (varint), length (varint), value (varint or opaque) }.
// We build a Chrome 147-shaped block so a fingerprinter sees Chrome-like values + ordering.

const varint = require('./varint')

const TP = {
	original_destination_connection_id: 0x00,
	max_idle_timeout: 0x01,
	stateless_reset_token: 0x02,
	max_udp_payload_size: 0x03,
	initial_max_data: 0x04,
	initial_max_stream_data_bidi_local: 0x05,
	initial_max_stream_data_bidi_remote: 0x06,
	initial_max_stream_data_uni: 0x07,
	initial_max_streams_bidi: 0x08,
	initial_max_streams_uni: 0x09,
	ack_delay_exponent: 0x0a,
	max_ack_delay: 0x0b,
	disable_active_migration: 0x0c,
	preferred_address: 0x0d,
	active_connection_id_limit: 0x0e,
	initial_source_connection_id: 0x0f,
	retry_source_connection_id: 0x10,
	version_information: 0x11,
	max_datagram_frame_size: 0x20,            // RFC 9221 — peer accepts DATAGRAM frames up to this size
	grease_quic_bit: 0x2ab2,
}

function tpVarint(id, value) {
	const v = varint.encode(value)
	return Buffer.concat([varint.encode(id), varint.encode(v.length), v])
}
function tpOpaque(id, bytes) {
	return Buffer.concat([varint.encode(id), varint.encode(bytes.length), bytes])
}
function tpEmpty(id) {
	return Buffer.concat([varint.encode(id), varint.encode(0)])
}

// Chrome 147 transport parameters profile. Values reverse-engineered from public packet captures.
function buildChrome147({ initialSourceConnectionId }) {
	return Buffer.concat([
		tpVarint(TP.max_idle_timeout, 30000),
		tpVarint(TP.initial_max_data, 15728640),
		tpVarint(TP.initial_max_stream_data_bidi_local, 6291456),
		tpVarint(TP.initial_max_stream_data_bidi_remote, 6291456),
		tpVarint(TP.initial_max_stream_data_uni, 6291456),
		tpVarint(TP.initial_max_streams_bidi, 100),
		tpVarint(TP.initial_max_streams_uni, 100),
		tpOpaque(TP.initial_source_connection_id, initialSourceConnectionId),
		// Accept up to 8 server-issued CIDs so we can rotate / migrate.
		tpVarint(TP.active_connection_id_limit, 8),
		// Advertise willingness to receive DATAGRAM frames up to 65535 bytes (RFC 9221 §3).
		tpVarint(TP.max_datagram_frame_size, 65535),
	])
}

// Decode a transport_parameters block (peer's) into a flat { id: value } map. Opaque-valued
// params (CIDs, tokens, preferred_address) come through as Buffer; varint-valued ones as Number.
function decode(buf) {
	const out = {}
	let off = 0
	while (off < buf.length) {
		const id = varint.decode(buf, off); off += id.length
		const len = varint.decode(buf, off); off += len.length
		const val = buf.subarray(off, off + len.value); off += len.value
		// Heuristic: known varint params we want to read get decoded; everything else stays raw.
		if (id.value === TP.max_datagram_frame_size || id.value === TP.max_idle_timeout ||
		    id.value === TP.initial_max_data || id.value === TP.initial_max_streams_bidi ||
		    id.value === TP.initial_max_streams_uni || id.value === TP.active_connection_id_limit) {
			out[id.value] = val.length > 0 ? varint.decode(val, 0).value : 0
		} else {
			out[id.value] = val
		}
	}
	return out
}

// Wrap into a TLS extension (ext type 0x0039 for QUIC-in-TLS, RFC 9001 §8.2).
function asTlsExtension(tpBlock) {
	const extType = Buffer.from([0x00, 0x39])
	const extLen = Buffer.alloc(2); extLen.writeUInt16BE(tpBlock.length, 0)
	return Buffer.concat([extType, extLen, tpBlock])
}

module.exports = { TP, buildChrome147, asTlsExtension, decode, tpVarint, tpOpaque, tpEmpty }
