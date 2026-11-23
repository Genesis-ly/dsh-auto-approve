/**
 * dsh-auto-approve — configuration normalisation.
 *
 * Config arrives from the cordis patch layer (`cordis.patch.yml`) and is
 * therefore untrusted: every field is validated here, and an unusable value
 * falls back to the conservative default instead of widening access.
 *
 * @module dsh-auto-approve/config
 */
import { readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { expandHome, globToRegExp, normalizePath } from './rules.js'

/** Conservative defaults: only the plugin directories this workspace edits. */
export const DEFAULTS = {
  enabled: true,
  dryRun: false,
  mode: 'denylist',
  grantMinutes: 10,
  tools: ['ops_bash', 'bash', 'pwsh', 'pwsh_bash'],
  allowRoots: ['~/.dsh/plugins', '~/.dsh/profiles/*/node_modules', '~/.dsh/dsh-auto-approve'],
  protectedPaths: [
    '~/.dsh/profiles/*/package.json',
    '~/.dsh/profiles/*/cordis.yml',
    '~/.dsh/profiles/*/cordis.patch.yml',
  ],
  maxCommandLength: 6000,
  maxAuditCommand: 300,
  auditPath: '~/.dsh/dsh-auto-approve/audit.jsonl',
  rememberLimit: 256,
}

/**
 * Expand wildcard directory segments (`profiles/<star>/node_modules`) into the
 * concrete absolute directories that exist right now.
 * @param {string} pattern - absolute pattern that may contain `<star>` segments.
 * @param {string} home - absolute home directory.
 * @returns {string[]} existing absolute directories.
 */
export function expandDirPattern(pattern, home) {
  const absolute = normalizePath(isAbsolute(expandHome(pattern, home)) ? expandHome(pattern, home) : resolve(home, expandHome(pattern, home)))
  const segments = absolute.split(/[\\/]+/)
  let frontier = [segments[0].endsWith(':') ? `${segments[0]}/` : segments[0]]
  for (const segment of segments.slice(1)) {
    const next = []
    for (const base of frontier) {
      if (segment === '*') {
        try {
          for (const entry of readdirSync(base, { withFileTypes: true })) {
            if (entry.isDirectory()) next.push(join(base, entry.name))
          }
        } catch {
          // A missing parent simply yields no expansions.
        }
      } else {
        next.push(join(base, segment))
      }
    }
    frontier = next
  }
  return frontier.map(normalizePath)
}

/**
 * Validate one string-list field.
 * @param {unknown} value - raw config value.
 * @param {string[]} fallback - defaults to use when unusable.
 * @returns {string[]} string entries only.
 */
function stringList(value, fallback) {
  if (!Array.isArray(value)) return fallback
  const entries = value.filter((entry) => typeof entry === 'string' && entry.trim() !== '')
  return entries.length > 0 ? entries : fallback
}

/**
 * Normalise a positive integer field.
 * @param {unknown} value - raw config value.
 * @param {number} fallback - default.
 * @returns {number} usable integer.
 */
function positiveInt(value, fallback) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

/**
 * Build the runtime config the plugin actually uses.
 * @param {unknown} raw - config object from the cordis patch layer.
 * @param {NodeJS.ProcessEnv} [env] - environment override source (tests).
 * @returns {object} normalised config.
 */
export function normalizeConfig(raw, env = process.env) {
  const source = raw !== null && typeof raw === 'object' ? /** @type {Record<string, unknown>} */ (raw) : {}
  const home = env.DSH_AUTO_APPROVE_HOME ?? homedir()
  const allowPatterns = stringList(source.allowRoots, DEFAULTS.allowRoots)
  const allowRoots = allowPatterns.flatMap((pattern) => {
    if (!pattern.includes('*')) {
      const expanded = expandHome(pattern, home)
      return [normalizePath(isAbsolute(expanded) ? expanded : resolve(home, expanded))]
    }
    return expandDirPattern(pattern, home)
  })
  const protectedPatterns = stringList(source.protectedPaths, DEFAULTS.protectedPaths)
    .flatMap((pattern) => {
      if (!pattern.includes('*')) {
        const expanded = expandHome(pattern, home)
        return [normalizePath(isAbsolute(expanded) ? expanded : resolve(home, expanded))]
      }
      return [pattern]
    })
    .map((pattern) => globToRegExp(normalizePath(expandHome(pattern, home))))

  const auditPathRaw = source.auditPath
  const auditPath =
    typeof auditPathRaw === 'string' && auditPathRaw.trim() !== ''
      ? normalizePath(resolve(home, expandHome(auditPathRaw, home)))
      : normalizePath(resolve(home, expandHome(DEFAULTS.auditPath, home)))

  return {
    enabled: source.enabled !== false,
    dryRun: source.dryRun === true,
    mode: ['strict', 'window', 'denylist', 'both'].includes(source.mode) ? source.mode : DEFAULTS.mode,
    grantMinutes: typeof source.grantMinutes === 'number' && Number.isFinite(source.grantMinutes) && source.grantMinutes >= 0
      ? source.grantMinutes
      : DEFAULTS.grantMinutes,
    tools: stringList(source.tools, DEFAULTS.tools),
    allowRoots,
    allowPatterns,
    protectedPatterns,
    maxCommandLength: positiveInt(source.maxCommandLength, DEFAULTS.maxCommandLength),
    maxAuditCommand: positiveInt(source.maxAuditCommand, DEFAULTS.maxAuditCommand),
    auditPath,
    rememberLimit: positiveInt(source.rememberLimit, DEFAULTS.rememberLimit),
    home: normalizePath(home),
  }
}
