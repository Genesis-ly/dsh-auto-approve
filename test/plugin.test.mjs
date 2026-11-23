import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { apply, inject, name } from '../lib/index.js'

const HOME = 'C:\\Users\\test'
const SESSION = 'session-test'

/**
 * Minimal cordis context: records handlers, no services, silent logger.
 * @returns {{ctx: object, handlers: Map<string, Array<Function>>, order: string[]}} harness.
 */
function fakeCtx() {
  const handlers = new Map()
  const order = []
  const ctx = {
    logger: { info: () => {}, warn: () => {} },
    on(event, handler, options) {
      order.push(`${event}${options?.prepend === true ? ':prepend' : ''}`)
      if (!handlers.has(event)) handlers.set(event, [])
      handlers.get(event).push({ handler, options })
      return () => {}
    },
  }
  return { ctx, handlers, order }
}

/**
 * Drive one approval request through the registered answerer.
 * @param {object} harness - fake context.
 * @param {object} request - approval request.
 * @param {string} downstream - what the human/UI answers.
 * @returns {Promise<{outcome: string, askedHuman: boolean}>} result.
 */
async function ask(harness, request, downstream = 'allowed-once') {
  const entry = harness.handlers.get('approval/request')[0]
  let askedHuman = false
  const next = () => {
    askedHuman = true
    return Promise.resolve(downstream)
  }
  const outcome = await entry.handler(request, next)
  return { outcome, askedHuman }
}

test('plugin shape matches the cordis contract', () => {
  assert.equal(name, 'dsh-auto-approve')
  assert.deepEqual(inject, ['approval', 'tools'])
})

test('registers a recorder and a prepended answerer', () => {
  const harness = fakeCtx()
  apply(harness.ctx, { auditPath: join(tmpdir(), 'dsh-auto-approve-test', 'audit.jsonl'), mode: 'denylist' })
  assert.equal(harness.handlers.has('tools/pre-execute'), true)
  assert.equal(harness.handlers.has('approval/request'), true)
  assert.equal(harness.handlers.get('approval/request')[0].options.prepend, true, 'answerer must prepend')
})

test('answers a real-world install script and audits it', async () => {
  const auditPath = join(tmpdir(), 'dsh-auto-approve-test', 'audit.jsonl')
  rmSync(join(tmpdir(), 'dsh-auto-approve-test'), { recursive: true, force: true })
  const harness = fakeCtx()
  apply(harness.ctx, { auditPath, mode: 'denylist' })

  const command = "set -e\nDST=~/.dsh/plugins/x\nmkdir -p \"$DST/lib\"\ncp lib/index.js \"$DST/lib/\"\n"
  const record = harness.handlers.get('tools/pre-execute')[0].handler
  const callId = 'call-1'
  const forwarded = await record({ callId, name: 'ops_bash', arguments: { command } }, () => Promise.resolve({ kind: 'allow' }))
  assert.deepEqual(forwarded, { kind: 'allow' }, 'recorder must forward the decision unchanged')

  const request = {
    toolName: 'ops_bash',
    callId,
    agent: { session: { id: SESSION, cwd: 'C:\\Users\\test\\dsh-work' } },
  }
  const result = await ask(harness, request)
  assert.equal(result.askedHuman, false, 'must not reach the human')
  assert.equal(result.outcome, 'allowed-once')

  const lines = readFileSync(auditPath, 'utf8').trim().split('\n')
  const last = JSON.parse(lines[lines.length - 1])
  assert.equal(last.decided, 'allowed-once')
  assert.equal(last.via, 'denylist')
  assert.equal(last.tool, 'ops_bash')
})

test('delegates dangerous and unknown calls to the human', async () => {
  const auditPath = join(tmpdir(), 'dsh-auto-approve-test', 'audit2.jsonl')
  const harness = fakeCtx()
  apply(harness.ctx, { auditPath, mode: 'denylist' })
  const record = harness.handlers.get('tools/pre-execute')[0].handler

  await record(
    { callId: 'bad', name: 'ops_bash', arguments: { command: 'rm -rf ~/.dsh/plugins/x' } },
    () => Promise.resolve({ kind: 'allow' }),
  )
  const denied = await ask(harness, {
    toolName: 'ops_bash',
    callId: 'bad',
    agent: { session: { id: SESSION, cwd: 'C:\\tmp' } },
  })
  assert.equal(denied.askedHuman, true, 'destructive command reaches the human')
  assert.equal(denied.outcome, 'allowed-once', 'the human answer is passed through unchanged')

  const unknown = await ask(harness, { toolName: 'ops_bash', callId: 'never-recorded', agent: { session: { id: SESSION, cwd: 'C:\\tmp' } } })
  assert.equal(unknown.askedHuman, true, 'unknown callId reaches the human')
})

test('disabled config installs nothing', () => {
  const harness = fakeCtx()
  apply(harness.ctx, { enabled: false })
  assert.equal(harness.handlers.size, 0)
})
