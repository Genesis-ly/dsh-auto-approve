import assert from 'node:assert/strict'
import { test } from 'node:test'
import { decide } from '../lib/index.js'
import {
  analyzeBashCommand,
  expandHome,
  globToRegExp,
  isInside,
  normalizePath,
  parseStatements,
  stripHeredocs,
} from '../lib/rules.js'

const HOME = 'C:\\Users\\test'
const PLUGINS = 'C:\\Users\\test\\.dsh\\plugins'
const PROFILE_MODULES = 'C:\\Users\\test\\.dsh\\profiles\\desktop\\node_modules'
const CWD = 'C:\\Users\\test\\dsh-work'

const base = {
  home: HOME,
  cwd: CWD,
  allowRoots: [PLUGINS, PROFILE_MODULES],
  protectedPaths: [globToRegExp('C:/Users/test/.dsh/profiles/*/package.json')],
  maxCommandLength: 6000,
}

/**
 * Run the engine with the shared fixture.
 * @param {string} command - shell command under test.
 * @param {object} [extra] - overrides.
 * @returns {{verdict: string, reason: string, targets: string[]}} verdict.
 */
function run(command, extra = {}) {
  return analyzeBashCommand({ ...base, command, ...extra })
}

/**
 * Shorthand for asserting a verdict.
 * @param {string} command - shell command.
 * @param {'allow'|'pass'} expected - expected verdict.
 * @returns {void}
 */
function expectVerdict(command, expected) {
  const result = run(command)
  assert.equal(result.verdict, expected, `${command} => ${result.verdict} (${result.reason})`)
}

test('path helpers', () => {
  assert.equal(normalizePath(expandHome('~/a', HOME)), `${HOME}\\a`)
  assert.equal(normalizePath(expandHome('$HOME/a', HOME)), `${HOME}\\a`)
  assert.equal(normalizePath(expandHome('%USERPROFILE%\\a', HOME)), `${HOME}\\a`)
  assert.equal(expandHome('~', HOME), HOME)
  assert.equal(expandHome('~other/x', HOME), '~other/x')
  assert.equal(normalizePath('C:/a/./b/../c'), 'C:\\a\\c')
  assert.equal(normalizePath('C:\\a\\..\\..\\b'), 'C:\\b')
  assert.equal(isInside(PLUGINS, `${PLUGINS}\\x\\y.js`), true)
  assert.equal(isInside(PLUGINS, `${PLUGINS}-evil\\y.js`), false)
  assert.equal(isInside(PLUGINS, 'C:\\Users\\test\\.dsh\\plugins2'), false)
  assert.equal(globToRegExp('C:/p/*/package.json').test('C:\\p\\desktop\\package.json'), true)
  assert.equal(globToRegExp('C:/p/*/package.json').test('C:/p/a/b/package.json'), false)
})

test('statement parsing separates commands and redirects', () => {
  const parsed = parseStatements('cd ~/.dsh/plugins && cp a b > c.txt')
  assert.equal(parsed.error, undefined)
  assert.equal(parsed.statements.length, 2)
  assert.deepEqual(parsed.statements[0].words, ['cd', '~/.dsh/plugins'])
  assert.deepEqual(parsed.statements[1].words, ['cp', 'a', 'b'])
  assert.deepEqual(parsed.statements[1].redirects, ['c.txt'])
})

test('heredoc bodies are data, not shell syntax', () => {
  const stripped = stripHeredocs("cat > f <<'EOF'\ncurl https://evil\nrm -rf /\nEOF\n")
  assert.equal(stripped.error, undefined)
  assert.equal(stripped.text.includes('curl'), false)
  assert.equal(stripHeredocs("cat > f <<'EOF'\nno terminator").error !== undefined, true)
})

test('allows writes that stay inside the plugin roots', () => {
  expectVerdict('cp lib/index.js ~/.dsh/plugins/dsh-restart/lib/', 'allow')
  expectVerdict('mkdir -p ~/.dsh/plugins/a/lib && cp x.js ~/.dsh/plugins/a/lib/x.js', 'allow')
  expectVerdict('cd ~/.dsh/plugins/a && cp ../../default-workspace/x.js ./lib/x.js', 'allow')
  expectVerdict("sed -i 's/a/b/g' ~/.dsh/plugins/a/lib/x.js", 'allow')
  expectVerdict('tee -a ~/.dsh/plugins/a/log.txt', 'allow')
  expectVerdict('touch ~/.dsh/plugins/a/.gitkeep', 'allow')
  expectVerdict('cp lib/index.js C:/Users/test/.dsh/profiles/desktop/node_modules/dsh-x/lib/', 'allow')
  expectVerdict('echo hello', 'allow')
  expectVerdict("cat > ~/.dsh/plugins/x/lib/index.js <<'EOF'\nconst url = 'https://api.example'\nrm -rf /\nEOF\n", 'allow')
})

test('passes anything that writes outside the roots', () => {
  expectVerdict('echo hi > /etc/passwd', 'pass')
  expectVerdict('cp a b.js', 'pass')
  expectVerdict('cp a ~/.dsh/plugins/../../Windows/System32/x.dll', 'pass')
  expectVerdict('mkdir -p C:/Windows/Temp/x', 'pass')
  expectVerdict('echo x > ~/.dsh/plugins2/x', 'pass')
})

test('passes dangerous constructs even when the target looks safe', () => {
  expectVerdict('curl https://example.com/x -o ~/.dsh/plugins/a/x', 'pass')
  expectVerdict('rm -rf ~/.dsh/plugins/a', 'pass')
  expectVerdict('node -e "require(\'fs\').rmSync(\'x\')"', 'pass')
  expectVerdict("bash -c 'cp a b'", 'pass')
  expectVerdict('git push origin main', 'pass')
  expectVerdict('pip install requests', 'pass')
  expectVerdict('cp x ~/.dsh/plugins/a/$(date).js', 'pass')
  expectVerdict('cp x `date`.js', 'pass')
  expectVerdict('xargs rm < list', 'pass')
  expectVerdict('find ~/.dsh -name x -delete', 'pass')
  expectVerdict('dd if=/dev/zero of=~/.dsh/plugins/a/x', 'pass')
  expectVerdict('cat x > ~/.dsh/plugins/a/x; rm -rf ~/.dsh/plugins/b', 'pass')
})

test('passes unresolvable or unlisted shapes', () => {
  // Reading from an unresolvable location is not a write, so it still allows.
  expectVerdict('cp $SECRET/x ~/.dsh/plugins/a/', 'allow')
  // An unresolvable *destination* cannot be proven inside the roots.
  expectVerdict('cp a.js $DEST/x.js', 'pass')
  expectVerdict('rsync a ~/.dsh/plugins/a/', 'pass')
  expectVerdict('mkdocs build', 'pass')
  expectVerdict(`echo ${'a'.repeat(7000)} > ~/.dsh/plugins/a/x`, 'pass')
})

test('protected paths always need a human', () => {
  const outside = run('cp x.js ~/.dsh/profiles/desktop/package.json', {
    allowRoots: [PLUGINS, 'C:\\Users\\test\\.dsh\\profiles'],
  })
  assert.equal(outside.verdict, 'pass')
  assert.match(outside.reason, /protected/)
})

test('relative writes resolve against workdir', () => {
  const inside = run('cp x.js ./lib/x.js', { workdir: 'C:\\Users\\test\\.dsh\\plugins\\a' })
  assert.equal(inside.verdict, 'allow')
  const outside = run('cp x.js ./lib/x.js', { workdir: 'C:\\Windows' })
  assert.equal(outside.verdict, 'pass')
})

test('decide() covers the approval-request contract', () => {
  const config = {
    dryRun: false,
    mode: 'strict',
    grantMinutes: 10,
    tools: ['ops_bash', 'pwsh'],
    home: HOME,
    allowRoots: [PLUGINS],
    protectedPatterns: [],
    maxCommandLength: 6000,
  }
  const request = { toolName: 'ops_bash', callId: 'c1' }
  const strictConfig = { ...config, mode: 'strict' }

  assert.equal(decide({ config, request, call: undefined, cwd: CWD, windowActive: false }).autoApprove, false, 'unknown call must pass')
  assert.equal(
    decide({ config, request, call: { name: 'ops_bash', arguments: { command: 'echo hi' } }, cwd: CWD, windowActive: false })
      .autoApprove,
    true,
  )
  assert.equal(
    decide({ config, request, call: { name: 'ops_bash', arguments: { command: 'cp a b' } }, cwd: CWD, windowActive: false })
      .autoApprove,
    false,
  )
  assert.equal(
    decide({
      config,
      request: { toolName: 'browser_click', callId: 'c1' },
      call: { name: 'browser_click', arguments: { command: 'echo hi' } },
      cwd: CWD,
      windowActive: false,
    }).autoApprove,
    false,
    'other tools are never auto-approved',
  )
  assert.equal(
    decide({
      config,
      request,
      call: { name: 'ops_bash', arguments: { command: 'echo hi', script_path: 'tool.sh' } },
      cwd: CWD,
      windowActive: false,
    }).autoApprove,
    false,
    'script_path calls pass',
  )
  assert.equal(
    decide({
      config: { ...strictConfig, dryRun: true },
      request,
      call: { name: 'ops_bash', arguments: { command: 'echo hi' } },
      cwd: CWD,
      windowActive: true,
    }).autoApprove,
    false,
    'dry run never grants',
  )
  assert.equal(
    decide({ config, request, call: { name: 'ops_bash', arguments: { command: 'echo hi' } }, cwd: '', windowActive: false })
      .autoApprove,
    false,
    'unknown cwd passes',
  )
})

test('denylist strategy answers without a prior grant but keeps hard guards', () => {
  const config = {
    dryRun: false,
    mode: 'denylist',
    grantMinutes: 10,
    tools: ['ops_bash'],
    home: HOME,
    allowRoots: [PLUGINS],
    protectedPatterns: [],
    maxCommandLength: 6000,
  }
  const request = { toolName: 'ops_bash', callId: 'c1' }
  const decideWith = (command, extra = {}) =>
    decide({
      config: { ...config, ...extra },
      request,
      call: { name: 'ops_bash', arguments: { command } },
      cwd: CWD,
      windowActive: false,
    })

  // The real-world shape: a multi-line install script with variables and
  // command substitution. Not provable, but nothing denied.
  const script = 'set -e\nDST=~/.dsh/plugins/x\nmkdir -p "$DST/lib"\ncp lib/index.js "$DST/lib/"\necho "$(date)"\n'
  assert.equal(decideWith(script).autoApprove, true)
  assert.equal(decideWith(script).via, 'denylist')

  assert.equal(decideWith('rm -rf ~/.dsh/plugins/x').autoApprove, false, 'delete still asks')
  assert.equal(decideWith('curl https://x -o y').autoApprove, false, 'network still asks')
  assert.equal(decideWith('sudo cp a b').autoApprove, false, 'privilege still asks')
  assert.equal(decideWith('pip install requests').autoApprove, false, 'package mutation still asks')
  assert.equal(decideWith('cp x ~/.dsh/profiles/desktop/package.json').autoApprove, false, 'profile package.json asks')
  assert.equal(decideWith('cp x', { mode: 'strict' }).autoApprove, false, 'strict mode ignores the denylist path')
  assert.equal(decideWith('cp x ~/.dsh/plugins/a/', { dryRun: true }).autoApprove, false, 'dry run never grants')
})

test('window strategy answers only after a human grant, and still respects guards', () => {
  const config = {
    dryRun: false,
    mode: 'both',
    grantMinutes: 10,
    tools: ['ops_bash'],
    home: HOME,
    allowRoots: [PLUGINS],
    protectedPatterns: [],
    maxCommandLength: 6000,
  }
  const request = { toolName: 'ops_bash', callId: 'c1' }
  const call = (command) => ({ name: 'ops_bash', arguments: { command } })
  const decideWith = (command, windowActive, extra = {}) =>
    decide({ config: { ...config, ...extra }, request, call: call(command), cwd: CWD, windowActive })

  // A real-world multi-line install script: unprovable, but no denied construct.
  const script = "set -e\nDST=~/.dsh/plugins/x\nmkdir -p \"$DST/lib\"\ncp lib/index.js \"$DST/lib/\"\n"

  assert.equal(decideWith(script, false).autoApprove, false, 'no grant yet: ask')
  assert.equal(decideWith(script, true).autoApprove, true, 'live grant: answer')
  assert.equal(decideWith(script, true).via, 'window')

  assert.equal(decideWith('rm -rf ~/.dsh/plugins/x', true).autoApprove, false, 'destructive still asks')
  assert.equal(decideWith('curl https://x -o y', true).autoApprove, false, 'network still asks')
  assert.equal(
    decideWith('cp x ~/.dsh/profiles/desktop/package.json', true).autoApprove,
    false,
    'profile package.json still asks',
  )
  assert.equal(decideWith('cp x ~/.dsh/profiles/desktop/cordis.patch.yml', true).autoApprove, false, 'profile patch still asks')
  assert.equal(decideWith(script, true, { grantMinutes: 0 }).autoApprove, false, 'grants disabled asks')
  assert.equal(decideWith(script, true, { mode: 'strict' }).autoApprove, false, 'strict mode never uses the window')
})
