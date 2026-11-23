/**
 * dsh-auto-approve — pure rule engine.
 *
 * Decides whether ONE pending shell escalation may be granted without a human.
 * No I/O, no clock, no globals: everything comes from the argument object so the
 * whole policy is unit-testable.
 *
 * Design bias: **deny (pass to the human) on any doubt**. `pass` is never a
 * rejection — it only means "this plugin declines to answer", so the normal
 * approval UI still gets to ask.
 *
 * @module dsh-auto-approve/rules
 */

/** Shell verbs whose writes this plugin is willing to reason about. */
const WRITE_VERBS = new Set(['cp', 'mv', 'mkdir', 'touch', 'tee', 'install', 'truncate'])

/** Verbs that never write by themselves. */
const READ_VERBS = new Set(['cat', 'echo', 'printf', 'ls', 'true', 'chmod-noop'])

/** Control-flow words and shell builtins that never write by themselves. */
const NOOP_VERBS = new Set(['true', 'false', ':', 'cd', 'set', 'export', 'unset', 'shift', 'local', 'readonly', 'wait', 'sleep'])

/** `NAME=value` assignment statements. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

/**
 * Dangerous constructs. The third element marks a *hard* denial: it blocks every
 * strategy. `false` marks a proof-breaking construct — it makes the static proof
 * impossible but is not itself dangerous, so the window strategy may still answer
 * (command substitution bodies are plain text and are scanned by every rule).
 */
const DANGER = [
  ['command substitution', /[`]|\$\(/, false],
  ['obfuscated execution', /(?<![\w.-])(eval|exec|xargs)(?![\w.-])/, true],
  ['sourcing a script', /(?<![\w.-])source(?![\w.-])/, true],
  ['privilege escalation', /(?<![\w.-])(sudo|runas|Start-Process)(?![\w.-])/i, true],
  [
    'network access',
    /(?<![\w.-])(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|netcat|ssh|scp|sftp|ftp)(?![\w.-])/i,
    true,
  ],
  ['git mutation', /(?<![\w.-])git\s+(push|remote|reset|clean|rebase|filter-branch)(?![\w.-])/i, true],
  [
    'system mutation',
    /(?<![\w.-])(reg(add)?|reg\s+(add|delete)|sc\s+delete|schtasks|shutdown|Restart-Computer|Stop-Computer|bcdedit|diskpart|taskkill|wmic)(?![\w.-])/i,
    true,
  ],
  [
    'package or registry mutation',
    /(?<![\w.-])(pip|pip3|npm|pnpm|yarn|winget|choco|scoop|cargo)\s+(install|add|remove|publish|uninstall|upgrade)(?![\w.-])/i,
    true,
  ],
  ['container or cluster control', /(?<![\w.-])(docker|kubectl|systemctl|service)(?![\w.-])/i, true],
  ['destructive delete', /(?<![\w.-])(rm|rmdir|del|rd|Remove-Item|mkfs|format|dd)(?![\w.-])/i, true],
  [
    'nested shell',
    /(?<![\w.-])(bash|sh|zsh|fish|pwsh|powershell|cmd)\s+(-c|\/c|-Command|-EncodedCommand)(?![\w.-])/i,
    true,
  ],
  ['inline interpreter', /(?<![\w.-])(node|python|python3|perl|ruby)\s+-(e|c)(?![\w.-])/i, true],
  ['find mutation', /(?<![\w.-])find\b[^\n]*\s-(delete|exec)\b/i, true],
  ['raw device write', /\/dev\/(sd|hd|nvme|disk)/i, true],
]

/** Characters that make a path impossible to resolve statically. */
const UNRESOLVED = /\$|%[A-Za-z_]+%?/

/**
 * Expand the only variables a path may contain: the user's home in its usual
 * spellings. Anything else stays unresolved on purpose.
 * @param {string} token - raw path token.
 * @param {string} home - absolute home directory.
 * @returns {string} token with home variables substituted.
 */
export function expandHome(token, home) {
  const patterns = [/^~(?![\w.-])/, /^\$\{HOME\}(?![\w.-])/, /^\$HOME(?![\w.-])/, /^%USERPROFILE%/i, /^%HOMEDRIVE%%HOMEPATH%/i]
  for (const pattern of patterns) {
    if (pattern.test(token)) return home + token.replace(pattern, '')
  }
  return token
}

/**
 * Whether `target` is `root` or lives underneath it.
 * Windows comparisons are case-insensitive because the filesystem is.
 * @param {string} root - absolute, normalized allow root.
 * @param {string} target - absolute, normalized write target.
 * @returns {boolean} containment verdict.
 */
export function isInside(root, target) {
  const a = process.platform === 'win32' ? root.toLowerCase() : root
  const b = process.platform === 'win32' ? target.toLowerCase() : target
  if (b === a) return true
  const sep = a.endsWith('/') || a.endsWith('\\') ? '' : a.includes('\\') ? '\\' : '/'
  return b.startsWith(a + sep)
}

/**
 * First dangerous construct in a command, scanning only executable text.
 * @param {string} command - raw shell command.
 * @returns {string | undefined} the danger label, or undefined when clean.
 */
export function firstDanger(command) {
  if (typeof command !== 'string') return 'not a string'
  const heredoc = stripHeredocs(command)
  if (heredoc.error !== undefined) return heredoc.error
  for (const [label, pattern, hard] of DANGER) {
    if (hard === true && pattern.test(heredoc.text)) return label
  }
  return undefined
}

/**
 * Turn a glob (only `*` and `**` are meaningful) into an anchored RegExp.
 * @param {string} glob - pattern such as `C:/Users/x/.dsh/profiles/*'+'/package.json`.
 * @returns {RegExp} matcher over normalized paths.
 */
export function globToRegExp(glob) {
  const normalized = glob.replace(/[\\/]+/g, '/')
  const escaped = normalized.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const separatorAware = escaped.replace(/\//g, '[\\\\/]')
  const body = separatorAware.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^\\\\/]*').replace(/\u0000/g, '.*')
  return new RegExp(`^${body}$`, process.platform === 'win32' ? 'i' : '')
}

/**
 * Split a command into statements, honouring quotes and redirects.
 *
 * Returns `{ statements, error? }`. `error` means the command could not be
 * parsed without guessing, which the caller must treat as "pass to the human".
 *
 * @param {string} command - the raw shell command text.
 * @returns {{statements: Array<{words: string[], redirects: string[]}>, error?: string}}
 */
export function parseStatements(command) {
  /** @type {Array<{words: string[], redirects: string[]}>} */
  const statements = []
  let words = []
  let redirects = []
  let word = ''
  let started = false
  let quote = ''
  let pendingRedirect = false
  let danglingRedirect = false

  const flushWord = () => {
    if (!started) return
    if (pendingRedirect) {
      // A redirect with no target yet: keep waiting for the next word.
      if (word === '') return
      redirects.push(word)
      pendingRedirect = false
    } else {
      words.push(word)
    }
    word = ''
    started = false
  }
  const flushStatement = () => {
    flushWord()
    if (pendingRedirect) {
      danglingRedirect = true
      pendingRedirect = false
    }
    if (words.length > 0 || redirects.length > 0) statements.push({ words, redirects })
    words = []
    redirects = []
  }

  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i]
    if (quote !== '') {
      if (ch === quote) {
        quote = ''
        started = true
      } else if (quote === '"' && ch === '\\' && i + 1 < command.length) {
        word += command[i + 1]
        i += 1
        started = true
      } else {
        word += ch
        started = true
      }
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      started = true
      continue
    }
    if (ch === '\\' && i + 1 < command.length) {
      word += command[i + 1]
      i += 1
      started = true
      continue
    }
    if (ch === '>') {
      flushWord()
      let cursor = i + 1
      if (command[cursor] === '>') cursor += 1
      if (command[cursor] === '&') {
        // File-descriptor duplication (`2>&1`, `>&2`): never a file target.
        while (cursor + 1 < command.length && !/[\s;&|]/.test(command[cursor + 1])) cursor += 1
        i = cursor
        pendingRedirect = false
        started = false
        word = ''
        continue
      }
      i = cursor - 1
      pendingRedirect = true
      started = true
      word = ''
      continue
    }
    if (ch === '<') {
      flushWord()
      // Input redirection never creates a file; skip its target.
      pendingRedirect = false
      started = false
      word = ''
      if (command[i + 1] === '<') i += 1
      continue
    }
    if (ch === ';' || ch === '\n' || ch === '&' || ch === '|') {
      flushStatement()
      if ((ch === '&' || ch === '|') && command[i + 1] === ch) i += 1
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flushWord()
      continue
    }
    word += ch
    started = true
  }
  if (quote !== '') return { statements: [], error: 'unbalanced quotes' }
  flushStatement()
  if (danglingRedirect) return { statements: [], error: 'redirect without a target' }
  return { statements }
}

/**
 * Remove heredoc bodies so their data is not scanned as shell syntax.
 * A heredoc body is data written to a file, not commands executed.
 *
 * @param {string} command - raw command text.
 * @returns {{text: string, error?: string}} command text without heredoc bodies.
 */
export function stripHeredocs(command) {
  const lines = command.split('\n')
  const kept = []
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    const marker = /(?:^|\s)<<-?\s*(?:(['"])([^'"]+)\1|([A-Za-z_][\w.-]*))/.exec(line)
    if (marker === null) {
      kept.push(line)
      continue
    }
    const delimiter = marker[2] ?? marker[3]
    kept.push(line.replace(marker[0], (match) => match.replace(/<<-?\s*(\S+)$/, '')))
    let closed = false
    for (i += 1; i < lines.length; i += 1) {
      if (lines[i].trim() === delimiter) {
        closed = true
        break
      }
    }
    if (!closed) return { text: kept.join('\n'), error: `unterminated heredoc ${delimiter}` }
  }
  return { text: kept.join('\n') }
}

/**
 * Write targets a single statement would create or modify.
 * @param {{words: string[], redirects: string[]}} statement - parsed statement.
 * @param {string} cwd - directory the statement runs in.
 * @param {(token: string, cwd: string) => ({ok: true, path: string} | {ok: false, reason: string})} resolve - path resolver.
 * @returns {{targets: string[], error?: string}} absolute write targets, or a reason it is undecidable.
 */
export function writeTargetsOf(statement, cwd, resolve) {
  const targets = []
  const verb = statement.words[0] ?? ''
  const args = statement.words.slice(1).filter((w) => !w.startsWith('-'))
  const add = (token) => {
    const resolved = resolve(token, cwd)
    if (!resolved.ok) {
      targets.push({ error: resolved.reason })
      return
    }
    targets.push(resolved.path)
  }

  for (const redirect of statement.redirects) add(redirect)

  if (WRITE_VERBS.has(verb)) {
    const positional = []
    for (let i = 1; i < statement.words.length; i += 1) {
      const word = statement.words[i]
      if (word === '-t' || word === '--target-directory') {
        const dir = statement.words[i + 1]
        if (dir !== undefined) add(dir)
        i += 1
        continue
      }
      if (word.startsWith('-')) continue
      positional.push(word)
    }
    if (verb === 'mkdir' || verb === 'touch' || verb === 'tee') {
      for (const word of positional) add(word)
    } else if (positional.length > 0) {
      add(positional[positional.length - 1])
    }
  } else if (verb === 'sed') {
    const inPlace = statement.words.some((w) => w === '-i' || /^-i.+/.test(w) || w.startsWith('--in-place'))
    if (inPlace && args.length > 0) add(args[args.length - 1])
  }

  const errors = targets.filter((t) => typeof t !== 'string').map((t) => t.error)
  if (errors.length > 0) return { targets: [], error: errors[0] }
  return { targets }
}

/**
 * Evaluate one pending escalation.
 *
 * @param {object} input - evaluation input.
 * @param {string} input.command - the shell command about to run unsandboxed.
 * @param {string} [input.workdir] - requested working directory.
 * @param {string} input.cwd - session working directory used for relative paths.
 * @param {string} input.home - absolute home directory.
 * @param {string[]} input.allowRoots - absolute roots a write may touch.
 * @param {RegExp[]} input.protectedPaths - write targets that always need a human.
 * @param {number} input.maxCommandLength - commands longer than this pass.
 * @returns {{verdict: 'allow'|'pass', reason: string, targets: string[]}} the decision.
 */
export function analyzeBashCommand(input) {
  const { command, workdir, cwd, home, allowRoots, protectedPaths = [], maxCommandLength } = input
  const pass = (/** @type {string} */ code, /** @type {string} */ reason) => ({
    verdict: /** @type {const} */ ('pass'),
    code,
    reason,
    targets: [],
  })
  const allow = (/** @type {string[]} */ targets) => ({
    verdict: /** @type {const} */ ('allow'),
    code: 'ok',
    reason: 'all writes stay inside allow roots',
    targets,
  })

  if (typeof command !== 'string' || command.trim() === '') return pass('empty', 'empty command')
  if (command.length > maxCommandLength) return pass('length', `command longer than ${maxCommandLength} characters`)

  const heredoc = stripHeredocs(command)
  if (heredoc.error !== undefined) return pass('parse', heredoc.error)

  for (const [label, pattern, hard] of DANGER) {
    if (pattern.test(heredoc.text)) {
      return hard === true ? pass('danger', `contains ${label}`) : pass('unprovable', `contains ${label}`)
    }
  }

  const parsed = parseStatements(heredoc.text)
  if (parsed.error !== undefined) return pass('parse', parsed.error)
  if (parsed.statements.length === 0) return pass('empty', 'no statements')

  const resolvePath = (token, base) => {
    const expanded = expandHome(token, home)
    if (UNRESOLVED.test(expanded)) return { ok: /** @type {const} */ (false), reason: `unresolvable path token ${token}` }
    const absolute = /^([A-Za-z]:[\\/]|[\\/])/.test(expanded) ? expanded : joinPath(base, expanded)
    return { ok: /** @type {const} */ (true), path: normalizePath(absolute) }
  }

  let currentCwd = workdir === undefined || workdir === '' ? cwd : workdir
  const startResolved = resolvePath(currentCwd, cwd)
  if (!startResolved.ok) return pass('path', startResolved.reason)
  currentCwd = startResolved.path

  const writes = []
  for (const statement of parsed.statements) {
    const verb = statement.words[0]
    if (verb === undefined) {
      if (statement.redirects.length === 0) continue
    } else {
      const allowedVerb =
        WRITE_VERBS.has(verb) || READ_VERBS.has(verb) || NOOP_VERBS.has(verb) || verb === 'sed' || ASSIGNMENT.test(verb)
      if (!allowedVerb) return pass('verb', `verb "${verb}" is not on the auto-approve list`)
      if (verb === 'cd') {
        const target = statement.words[1]
        if (target === undefined) return pass('verb', 'bare cd')
        const moved = resolvePath(target, currentCwd)
        if (!moved.ok) return pass('path', moved.reason)
        currentCwd = moved.path
        continue
      }
    }
    const produced = writeTargetsOf(statement, currentCwd, resolvePath)
    if (produced.error !== undefined) return pass('path', produced.error)
    writes.push(...produced.targets)
  }

  if (writes.length === 0) return allow([])

  for (const target of writes) {
    if (protectedPaths.some((pattern) => pattern.test(target))) return pass('protected', `write to protected path ${target}`)
    if (!allowRoots.some((root) => isInside(root, target))) return pass('outside', `write outside allow roots: ${target}`)
  }
  return allow(writes)
}

/**
 * Join path segments without importing node:path, keeping the engine pure for
 * browser/test use. Windows separators are normalised by {@link normalizePath}.
 * @param {string} base - base path.
 * @param {string} relative - relative path.
 * @returns {string} joined path.
 */
export function joinPath(base, relative) {
  if (relative === '') return base
  const sep = base.includes('\\') ? '\\' : '/'
  return `${base.replace(/[\\/]+$/, '')}${sep}${relative}`
}

/**
 * Collapse `.` and `..` segments so containment checks cannot be defeated by
 * traversal.
 * @param {string} path - absolute path with possible dot segments.
 * @returns {string} normalized path.
 */
export function normalizePath(path) {
  const win = /^[A-Za-z]:/.test(path) || path.includes('\\')
  const sep = win ? '\\' : '/'
  const parts = path.split(/[\\/]+/)
  const out = []
  for (const part of parts) {
    if (part === '' && out.length === 0) continue
    if (part === '.' || part === '') continue
    if (part === '..') {
      if (out.length > 1) out.pop()
      continue
    }
    out.push(part)
  }
  const head = out.length > 0 ? out[0] : ''
  const tail = out.slice(1).join(sep)
  if (tail === '') return head
  return head.endsWith(':') ? `${head}${sep}${tail}` : `${head}${sep}${tail}`
}

export const internals = { WRITE_VERBS, READ_VERBS, NOOP_VERBS, DANGER }
