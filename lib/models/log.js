// Internal logger.
//
// Silent by default — a published library shouldn't write to stdout/stderr in normal
// operation; errors flow through `emit('error', ...)` per Node convention.
//
// Configuration:
//   HELLOJS_LOG=error|warn|info|debug|trace    — choose the level (default: silent/off)
//   HELLOJS_LOG_JSON=1                         — emit JSON-line records (one per line) for
//                                                ingestion into structured-log pipelines
//   HELLOJS_DEBUG=1                            — legacy alias for `trace`
//   -d on argv                                 — legacy alias for `trace`
//   ENV=development                            — legacy alias for `trace`
//
// In-process:
//   require('./log').setLevel('info')
//   require('./log').setJsonMode(true)
//
// Level ordering (each level shows itself + everything more severe):
//   off (0) < error (1) < warn (2) < info (3) < debug (4) < trace (5)

const LEVELS = { off: 0, error: 1, warn: 2, info: 3, debug: 4, trace: 5 }

function resolveInitialLevel() {
	const v = process.env.HELLOJS_LOG
	if (v && Object.prototype.hasOwnProperty.call(LEVELS, v.toLowerCase())) {
		return LEVELS[v.toLowerCase()]
	}
	if (process.env.HELLOJS_DEBUG === '1' || process.argv.includes('-d') || process.env.ENV === 'development') {
		return LEVELS.trace
	}
	return LEVELS.off
}

let currentLevel = resolveInitialLevel()
let jsonMode = process.env.HELLOJS_LOG_JSON === '1'

function setLevel(level) {
	if (typeof level === 'number') { currentLevel = level; return }
	const n = LEVELS[String(level).toLowerCase()]
	if (n != null) currentLevel = n
}

function getLevel() { return currentLevel }

function setJsonMode(enabled) { jsonMode = !!enabled }
function getJsonMode() { return jsonMode }

const ts = () => {
	const d = new Date()
	const pad = (n, w = 2) => String(n).padStart(w, '0')
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
		`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}:${pad(d.getMilliseconds(), 3)}`
}

const colored = (color, prefix, msg) => `\x1b[${color}m[${ts()}] ${prefix}${msg.join(' ')}\x1b[0m`

function jsonLine(level, prefix, args) {
	const rec = {
		ts: new Date().toISOString(),
		level,
		mod: prefix.trim() || null,
		msg: args.map((x) => typeof x === 'string' ? x : (() => { try { return JSON.stringify(x) } catch { return String(x) } })()).join(' '),
	}
	return JSON.stringify(rec)
}

const logger = (prefix = '') => {
	if (prefix !== '') prefix = `${prefix} `

	const emit = (level, color, label) => (...m) => {
		if (currentLevel < LEVELS[level]) return
		if (jsonMode) console.log(jsonLine(level, prefix, m))
		else console.log(colored(color, label + prefix, m))
	}

	const log = {}
	log.error   = (...m) => { emit('error', '31', '')(...m); return false }
	log.warn    = emit('warn', '33', '')
	log.success = (...m) => { emit('info', '32', '')(...m); return true }
	log.notify  = emit('info', '36', '')
	log.pretty  = emit('debug', '35', '')
	log.debug   = emit('debug', '1;37;40', '[DEBUG] ')
	log.trace   = emit('trace', '90', '[TRACE] ')
	return log
}

logger.setLevel = setLevel
logger.getLevel = getLevel
logger.setJsonMode = setJsonMode
logger.getJsonMode = getJsonMode
logger.LEVELS = LEVELS

module.exports = logger
