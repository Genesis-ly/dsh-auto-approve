/**
 * dsh-auto-approve — Host half.
 *
 * Problem this solves: under the `workspace-write` permission preset, any shell
 * command that needs to write outside the session workspace must ask the human.
 * In this workspace that is almost always the same safe operation — patching a
 * plugin under `~/.dsh/plugins` or `~/.dsh/profiles/<profile>/node_modules` —
 * so the same popup fires dozens of times per session and is always approved
 * (measured: 67 of 67 decided requests were `allowed-once`).
 *
 * Two hooks make it possible:
 * - `tools/pre-execute` records the pending call: approval requests carry only
 *   the tool name, a reason and a callId, never the arguments.
 * - `approval/request` answers the escalation. Answerers are waterfall
 *   listeners: returning an outcome ends the chain, `next()` delegates, and the
 *   promise `next()` resolves to exposes the downstream outcome — which is how
 *   a human grant is observed.
 *
 * Two decision strategies, both auditable and configurable (`mode`):
 * - `strict`: answer only when the command provably writes inside `allowRoots`.
 *   Real commands are multi-line scripts, so this rarely fires (measured 3/81).
 * - `window`: after a human approves one escalation in a session, answer the
 *   next `grantMinutes` minutes of shell escalations itself (measured 48/81).
 * - `denylist` (default): answer any shell escalation that carries no hard
 *   denied construct and does not touch profile config (measured 60/81). The
 *   guard is string matching over the command text, not a proof.
 * - `both`: strict proof OR the window rule.
 *
 * @module dsh-auto-approve
 */
import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { normalizeConfig } from './config.js'
import { analyzeBashCommand, firstDanger } from './rules.js'

/** Plugin id used by the profile patch layer. */
export const name = 'dsh-auto-approve'

/**
 * Services that must exist before the hooks are useful: the approval seam owns
 * the answerer waterfall, the tools service owns the pre-execute waterfall.
 */
export const inject = ['approval', 'tools']

/**
 * Coarse guard for profile configuration files, used by the window strategy
 * where the exact write targets may be unprovable.
 * @param {string} command - raw shell command.
 * @returns {boolean} whether the command appears to touch profile config.
 */
export function mentionsProtectedConfig(command) {
  if (typeof command !== 'string') return false
  if (/cordis\.(patch\.)?ya?ml/i.test(command)) return true
  return /profiles[\\/][^\\/\s"'`]+[\\/]package\.json/i.test(command)
}

/**
 * Best-effort session working directory across session shapes.
 * @param {unknown} agent - requesting agent.
 * @returns {string} absolute cwd, or an empty string when unknown.
 */
export function sessionCwd(agent) {
  const session = /** @type {any} */ (agent)?.session
  const candidate = session?.cwd ?? session?.header?.cwd ?? session?.meta?.cwd
  return typeof candidate === 'string' && candidate !== '' ? candidate : ''
}

/**
 * Truncate a string for the audit log without cutting a surrogate pair.
 * @param {string} value - raw text.
 * @param {number} limit - maximum characters.
 * @returns {string} bounded text.
 */
export function truncate(value, limit) {
  if (typeof value !== 'string') return ''
  if (value.length <= limit) return value
  return `${value.slice(0, limit)}…(${value.length} chars)`
}

/**
 * Answer a single approval request from the recorded call.
 *
 * Pure with respect to the plugin: it decides and explains, and the caller
 * performs the audit append. Kept separate so tests can drive it directly.
 *
 * @param {object} input - decision input.
 * @param {object} input.config - normalised config.
 * @param {{toolName?: string, callId?: string}} input.request - the approval request.
 * @param {{name: string, arguments: unknown} | undefined} input.call - recorded pending call.
 * @param {string} input.cwd - session working directory.
 * @param {boolean} input.windowActive - whether this session holds a live human grant.
 * @returns {{autoApprove: boolean, via: 'strict'|'window'|'none', code: string, reason: string, targets: string[]}} decision.
 */
export function decide(input) {
  const { config, request, call, cwd, windowActive } = input
  const pass = (/** @type {string} */ code, /** @type {string} */ reason) => ({
    autoApprove: false,
    via: /** @type {const} */ ('none'),
    code,
    reason,
    targets: [],
  })

  if (config.dryRun) return pass('dry-run', 'dry run: evaluate and audit only')
  if (request === undefined || typeof request.toolName !== 'string' || !config.tools.includes(request.toolName)) {
    return pass('tool', `tool "${String(request?.toolName)}" is not on the auto-approve list`)
  }
  if (call === undefined) return pass('unknown-call', 'no recorded call for this callId')
  const args = call.arguments
  if (args === null || typeof args !== 'object') return pass('no-args', 'call has no argument object')
  const bag = /** @type {Record<string, unknown>} */ (args)
  if (bag.script_path !== undefined) return pass('no-command', 'script_path call: the script body is not inspected')
  if (typeof bag.command !== 'string') return pass('no-command', 'call has no inline command')
  if (cwd === '') return pass('no-cwd', 'session working directory is unknown')

  const analysis = analyzeBashCommand({
    command: bag.command,
    workdir: typeof bag.workdir === 'string' ? bag.workdir : undefined,
    cwd,
    home: config.home,
    allowRoots: config.allowRoots,
    protectedPaths: config.protectedPatterns,
    maxCommandLength: config.maxCommandLength,
  })
  if (analysis.verdict === 'allow') {
    return { autoApprove: true, via: 'strict', code: 'ok', reason: analysis.reason, targets: analysis.targets }
  }

  if (config.mode === 'strict') return pass(analysis.code, `strict mode: ${analysis.reason}`)
  if (analysis.code === 'protected') return pass('protected', analysis.reason)

  const windowed = config.mode === 'window' || config.mode === 'both'
  if (windowed) {
    if (config.grantMinutes <= 0) return pass(analysis.code, `grant window disabled: ${analysis.reason}`)
    if (!windowActive) return pass(analysis.code, `no live human grant in this session: ${analysis.reason}`)
  }

  const danger = firstDanger(bag.command)
  if (danger !== undefined) return pass('danger', `blocked by denied construct: ${danger}`)
  if (bag.command.length > config.maxCommandLength) return pass('length', 'command too long for this strategy')
  if (mentionsProtectedConfig(bag.command)) return pass('protected', 'blocked: command mentions profile config')
  return {
    autoApprove: true,
    via: windowed ? 'window' : 'denylist',
    code: windowed ? 'window' : 'denylist',
    reason: windowed
      ? 'live human grant in this session and no denied construct'
      : 'no denied construct and no profile-config write',
    targets: [],
  }
}

/**
 * Append one audit record. Never throws: an unwritable log must not change any
 * approval outcome.
 * @param {object} config - normalised config.
 * @param {object} record - audit fields.
 * @returns {void}
 */
export function audit(config, record) {
  try {
    mkdirSync(dirname(config.auditPath), { recursive: true })
    appendFileSync(config.auditPath, `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`, 'utf8')
  } catch {
    // Auditing is best effort.
  }
}

/**
 * Install the recorder and the answerer.
 * @param {any} ctx - cordis plugin context.
 * @param {unknown} [rawConfig] - configuration from the patch layer.
 * @returns {void}
 */
export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  if (!config.enabled) {
    ctx.logger?.info?.('dsh-auto-approve: disabled by config')
    return
  }
  /** @type {Map<string, {name: string, arguments: unknown}>} */
  const calls = new Map()
  /** @type {Map<string, number>} session id -> grant expiry epoch ms */
  const grants = new Map()
  const grantMs = config.grantMinutes * 60 * 1000

  const remember = (/** @type {any} */ exec) => {
    if (exec === undefined || exec.callId === undefined) return
    calls.set(String(exec.callId), { name: exec.name, arguments: exec.arguments })
    while (calls.size > config.rememberLimit) {
      const oldest = calls.keys().next()
      if (oldest.done === true) break
      calls.delete(oldest.value)
    }
  }
  const windowActive = (/** @type {string | undefined} */ sessionId) => {
    if (sessionId === undefined || grantMs <= 0) return false
    const until = grants.get(sessionId)
    if (until === undefined) return false
    if (Date.now() >= until) {
      grants.delete(sessionId)
      return false
    }
    return true
  }
  const refreshGrant = (/** @type {string | undefined} */ sessionId) => {
    if (sessionId === undefined || grantMs <= 0) return
    grants.set(sessionId, Date.now() + grantMs)
  }

  // The recorder only observes: it forwards the decision it was given.
  ctx.on('tools/pre-execute', (exec, next) => {
    remember(exec)
    return next()
  })

  // The answerer runs first so an auto-approved call never reaches the UI.
  // `prepend` matters: the desktop approval forwarder is registered later with
  // push and never calls next(), so a plain registration would never run.
  ctx.on(
    'approval/request',
    (request, next) => {
      try {
        if (request?.signal?.aborted === true) return next()
        const sessionId = request?.agent?.session?.id
        const callId = request?.callId === undefined ? undefined : String(request.callId)
        const decision = decide({
          config,
          request,
          call: callId === undefined ? undefined : calls.get(callId),
          cwd: sessionCwd(request?.agent),
          windowActive: windowActive(sessionId),
        })
        audit(config, {
          tool: request?.toolName,
          callId,
          session: sessionId,
          decided: decision.autoApprove ? 'allowed-once' : 'pass-to-human',
          via: decision.via,
          code: decision.code,
          reason: decision.reason,
          targets: decision.targets,
        })
        if (decision.autoApprove) {
          if (decision.via === 'window') refreshGrant(sessionId)
          ctx.logger?.info?.(`dsh-auto-approve: granted ${String(request?.toolName)} via ${decision.via} (${decision.reason})`)
          return 'allowed-once'
        }
        const downstream = next()
        // A human grant is what arms the window; observe it without altering it.
        return typeof downstream?.then === 'function'
          ? downstream.then((outcome) => {
              if (outcome === 'allowed-once') refreshGrant(sessionId)
              return outcome
            })
          : downstream
      } catch (error) {
        // A bug here must never widen access: delegate to the normal chain.
        ctx.logger?.warn?.(`dsh-auto-approve: rule failure, passing to human: ${String(error?.message ?? error)}`)
        return next()
      }
    },
    { prepend: true },
  )
}
