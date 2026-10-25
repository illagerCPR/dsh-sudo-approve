/**
 * dsh-sudo-approve — Host half.
 *
 * Gates `bash` tool calls from the root agent that invoke sudo. The pending
 * command is published to the connected Web page, the user types the password
 * there, and only then does the call proceed. The password never enters the
 * model context, the session log, or any ordinary log line.
 *
 * Flow:
 *   tools/pre-execute  → ask the page, validate with `sudo -S -v`, allow
 *   tools/execute      → install a PATH shim + askpass helper, run, tear down
 *
 * The command line itself is never rewritten: the shim only adds `-A`, so the
 * job registry, sandbox policy, spill truncation and streaming output all stay
 * exactly as the bash tool composed them.
 *
 * @module dsh-sudo-approve
 */

import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

/** Plugin identity used in route paths, log lines and dir prefixes. */
const NAME = 'dsh-sudo-approve'
/** Bumped whenever a change has to be confirmed as live in the running Host. */
const BUILD = 6
/** Exact Fetch routes the browser half calls. */
const ROUTE_PREFIX = '/api/sudo-approve'
/** Fallback PATH when the Host process has none. */
const FALLBACK_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
/** Bounds for the tunable config values. */
const LIMITS = { timeoutMs: [5_000, 900_000], presenceWindowMs: [2_000, 300_000] }

/**
 * Generated `sudo` shim. It exists only while an approved command runs and only
 * adds `-A`; forms that sudo-rs refuses to combine with `-A` (`-k`, `-V`, `-h`)
 * are forwarded untouched.
 */
const SUDO_SHIM = `#!/bin/sh
for arg do
  case "$arg" in
    -k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)
      exec "@SUDO@" "$@" ;;
  esac
done
exec "@SUDO@" -A "$@"
`

/** Defaults; a `cordis.patch.yml` `config` object overrides them. */
const DEFAULTS = Object.freeze({
  /** Master switch. */
  enabled: true,
  /** `never` asks for the password every time; `session` reuses it in memory. */
  remember: 'never',
  /** How long the password panel stays open before it denies. */
  timeoutMs: 120_000,
  /** How recently a page must have polled to count as connected. */
  presenceWindowMs: 15_000,
  /** Tool names that can carry a shell command. */
  toolNames: Object.freeze(['bash']),
  /** Refuse to accept passwords when the deployment trusts non-loopback hosts. */
  allowRemoteDeployment: false,
  /** Remembered passwords idle for this long are dropped. */
  memoryTtlMs: 6 * 60 * 60 * 1000,
})

/**
 * Model-facing refusal texts. The model receives these as the pre-execute
 * denial reason, so they are written for an agent that must react sensibly.
 */
const MESSAGES = Object.freeze({
  noAgent: 'sudo 审批：无法确定发起该调用的智能体会话，已拒绝执行。',
  subagent: 'sudo 审批：子智能体不能申请 sudo，只有主会话可以直接执行 sudo 命令。请让主会话运行该命令。',
  background: 'sudo 审批：不支持 run_in_background 的 sudo 调用，请改为前台执行（需要你在按钮上确认）。',
  nested: 'sudo 审批：不支持在嵌套工具调用中执行 sudo。',
  sandbox: (mode) => `sudo 审批：当前会话处于 ${mode} 沙箱，沙箱内无法获取 root。请先把会话权限切换到 danger-full-access 再重试。`,
  remote: 'sudo 审批：本部署接受非回环地址的浏览器连接，插件拒绝在明文网络路径上接收密码（配置项 allowRemoteDeployment=false），已拒绝执行。',
  noClient: 'sudo 审批：当前没有已连接的浏览器页面可以弹出确认面板，已拒绝执行。请在页面打开后重试。',
  busy: 'sudo 审批：另一个 sudo 请求正在等待确认，同一时间只处理一个，已拒绝执行。',
  rejected: (reason) => (reason === undefined || reason === '' ? 'sudo 审批：用户拒绝执行该 sudo 命令。' : `sudo 审批：用户拒绝执行该 sudo 命令。拒绝理由：${reason}`),
  timeout: (seconds) => `sudo 审批：${seconds} 秒内没有收到确认，已拒绝执行。`,
  invalidPassword: 'sudo 审批：密码校验未通过。',
  internal: (detail) => `sudo 审批插件内部错误，已拒绝执行：${detail}`,
})

/** `true` for plain JSON-ish objects. */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Compact error text for logs and tool results. */
function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

/** One-line rejection reason; control characters folded, length capped. */
function normalizeReason(value) {
  if (typeof value !== 'string') return undefined
  const text = value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (text === '') return undefined
  return text.length > 200 ? `${text.slice(0, 200)}…` : text
}

/** Keep only well-typed editable settings; ranges are clamped when resolved. */
function sanitizePatch(raw) {
  const patch = {}
  if (!isPlainObject(raw)) return patch
  if (typeof raw.enabled === 'boolean') patch.enabled = raw.enabled
  if (raw.remember === 'never' || raw.remember === 'session') patch.remember = raw.remember
  if (typeof raw.timeoutMs === 'number' && Number.isFinite(raw.timeoutMs)) patch.timeoutMs = Math.round(raw.timeoutMs)
  if (typeof raw.presenceWindowMs === 'number' && Number.isFinite(raw.presenceWindowMs)) {
    patch.presenceWindowMs = Math.round(raw.presenceWindowMs)
  }
  if (typeof raw.allowRemoteDeployment === 'boolean') patch.allowRemoteDeployment = raw.allowRemoteDeployment
  return patch
}

/**
 * Read and clamp the plugin config.
 * @param raw - the Loader entry's `config` object.
 * @returns the resolved config.
 */
function resolveConfig(raw) {
  const input = isPlainObject(raw) ? raw : {}
  const clamp = (value, [min, max], fallback) =>
    typeof value === 'number' && Number.isFinite(value) ? Math.min(Math.max(value, min), max) : fallback
  const toolNames = Array.isArray(input.toolNames)
    ? input.toolNames.filter((name) => typeof name === 'string' && name !== '')
    : [...DEFAULTS.toolNames]
  return {
    enabled: input.enabled !== false,
    remember: input.remember === 'session' ? 'session' : 'never',
    timeoutMs: clamp(input.timeoutMs, LIMITS.timeoutMs, DEFAULTS.timeoutMs),
    presenceWindowMs: clamp(input.presenceWindowMs, LIMITS.presenceWindowMs, DEFAULTS.presenceWindowMs),
    memoryTtlMs: clamp(input.memoryTtlMs, LIMITS.timeoutMs, DEFAULTS.memoryTtlMs),
    toolNames: new Set(toolNames.length > 0 ? toolNames : [...DEFAULTS.toolNames]),
    allowRemoteDeployment: input.allowRemoteDeployment === true,
  }
}

/**
 * A `sudo` word at a command position: start of line, after a shell separator,
 * after a command substitution, or after a shell keyword. Environment
 * assignments in front of the verb are skipped.
 */
const SUDO_AT_COMMAND_POSITION =
  /(?:^|[;&|(\n{}`]|\$\(|(?:^|[\s;])then|(?:^|[\s;])do|(?:^|[\s;])else)\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s;&|()]*)\s+)*(?:sudo|sudoedit)(?=$|\s)/

/** Forms that never authenticate, so they must not be given `-A`. */
const METADATA_ONLY_SUDO =
  /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s;&|()]*)\s+)*(?:sudo|sudoedit)\s+(?:-k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)\s*;?\s*$/

/** Cap on displayed command lines; a longer script is truncated in the panel. */
const MAX_DISPLAY_LINES = 60
/** Cap on one displayed line. */
const MAX_DISPLAY_WIDTH = 400

/**
 * Turn a bash command into the lines the panel lists.
 * @param command - the tool's `command` argument.
 * @returns the displayed items and whether any of them needs real authority.
 */
function analyzeCommand(command) {
  const items = []
  let truncated = false
  for (const raw of command.split(/\r?\n/)) {
    const text = raw.trim()
    if (text === '') continue
    if (items.length >= MAX_DISPLAY_LINES) {
      truncated = true
      break
    }
    const sudo = SUDO_AT_COMMAND_POSITION.test(text)
    items.push({
      text: text.length > MAX_DISPLAY_WIDTH ? `${text.slice(0, MAX_DISPLAY_WIDTH)}…` : text,
      sudo,
      // `sudo -k` / `sudo -V` never authenticate, so they need no password.
      privileged: sudo && !METADATA_ONLY_SUDO.test(text),
    })
  }
  if (truncated) items.push({ text: `…（仅显示前 ${MAX_DISPLAY_LINES} 行）`, sudo: false, privileged: false, note: true })
  return { items, hasSudo: items.some((item) => item.privileged) }
}

/**
 * Find an executable on a PATH string without executing anything.
 * @param name - file name to look for.
 * @param searchPath - colon separated directories.
 * @returns the absolute path, or undefined.
 */
function findExecutable(name, searchPath) {
  for (const dir of searchPath.split(':')) {
    if (dir === '') continue
    const candidate = join(dir, name)
    try {
      const stat = statSync(candidate)
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return candidate
    } catch {
      // keep looking
    }
  }
  return undefined
}

/**
 * Install the Host half.
 * @param ctx - the plugin context.
 * @param rawConfig - the Loader entry `config`.
 */
export function apply(ctx, rawConfig) {
  const installConfig = isPlainObject(rawConfig) ? rawConfig : {}
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  const storePath = join(home, `${NAME}.json`)
  const auditLog = join(home, 'logs', `${NAME}.log`)

  /** Saved settings, when the file reads back as editable values. */
  function readStoredOverrides() {
    try {
      const parsed = JSON.parse(readFileSync(storePath, 'utf8'))
      return isPlainObject(parsed) ? sanitizePatch(parsed) : {}
    } catch {
      return {}
    }
  }

  let overrides = readStoredOverrides()
  /** Live config: install-time values under the saved settings. */
  let config = resolveConfig({ ...installConfig, ...overrides })
  const basePath = process.env.PATH ?? FALLBACK_PATH
  const baseAskpass = process.env.SUDO_ASKPASS
  const realSudo = findExecutable('sudo', basePath)
  const realSudoedit = findExecutable('sudoedit', basePath)

  /** Append one sanitized audit line; never receives a password. */
  function audit(event) {
    try {
      mkdirSync(dirname(auditLog), { recursive: true })
      appendFileSync(auditLog, `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`, {
        mode: 0o600,
      })
    } catch {
      // audit is best effort; never break the gate
    }
  }

  if (realSudo === undefined) {
    audit({ event: 'inactive', reason: 'sudo-not-found' })
    return
  }

  /** The one request currently waiting for the page, if any. */
  let inflight
  /** callId → validated password, released by the matching dispatch. */
  const armed = new Map()
  /** sessionId → { secret, usedAt } in `remember` mode. */
  const remembered = new Map()
  /** Timestamp of the last page poll; 0 means no page has ever polled. */
  let lastPollAt = 0
  /** Shim directories that must disappear on unload. */
  const installed = new Set()

  audit({ event: 'loaded', build: BUILD, remember: config.remember, timeoutMs: config.timeoutMs, sudo: realSudo })

  // ---------------------------------------------------------- settings ----
  /** Recompute live config, dropping remembered secrets that no longer apply. */
  function applyOverrides(next) {
    overrides = next
    config = resolveConfig({ ...installConfig, ...overrides })
    if (config.remember !== 'session') remembered.clear()
  }

  /** Persist a validated patch and apply it to new requests immediately. */
  function saveOverrides(patch) {
    const next = { ...overrides, ...patch }
    mkdirSync(dirname(storePath), { recursive: true })
    writeFileSync(storePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 })
    applyOverrides(next)
  }

  /** Drop every saved value, back to the install-time config. */
  function resetOverrides() {
    try {
      rmSync(storePath, { force: true })
    } catch {
      // best effort
    }
    applyOverrides({})
  }

  /** Values and bounds the settings page renders. */
  function settingsSnapshot() {
    return {
      build: BUILD,
      store: storePath,
      auditLog,
      limits: { timeoutMs: LIMITS.timeoutMs, presenceWindowMs: LIMITS.presenceWindowMs },
      values: {
        enabled: config.enabled,
        remember: config.remember,
        timeoutMs: config.timeoutMs,
        presenceWindowMs: config.presenceWindowMs,
        allowRemoteDeployment: config.allowRemoteDeployment,
      },
      install: sanitizePatch(installConfig),
      overrides: { ...overrides },
    }
  }

  // ------------------------------------------------------------- env ------
  /** Put the PATH shim and askpass helper in front of the inherited env. */
  async function materialize(secret) {
    const root = await mkdtemp(join(process.env.XDG_RUNTIME_DIR || tmpdir(), `${NAME}-`))
    installed.add(root)
    try {
      await chmod(root, 0o700)
      const bin = join(root, 'bin')
      await mkdir(bin, { mode: 0o700 })
      const passwordFile = join(root, 'askpass.txt')
      await writeFile(passwordFile, secret, { mode: 0o600 })
      await chmod(passwordFile, 0o600)
      const askpass = join(root, 'askpass.sh')
      await writeFile(askpass, `#!/bin/sh\nexec cat "${passwordFile}"\n`, { mode: 0o700 })
      await chmod(askpass, 0o700)
      await writeFile(join(bin, 'sudo'), SUDO_SHIM.replaceAll('@SUDO@', realSudo), { mode: 0o700 })
      await chmod(join(bin, 'sudo'), 0o700)
      if (realSudoedit !== undefined) {
        await writeFile(join(bin, 'sudoedit'), SUDO_SHIM.replaceAll('@SUDO@', realSudoedit), { mode: 0o700 })
        await chmod(join(bin, 'sudoedit'), 0o700)
      }
      process.env.PATH = `${bin}:${basePath}`
      process.env.SUDO_ASKPASS = askpass
      return { root, bin, askpass }
    } catch (error) {
      await dematerialize({ root })
      throw error
    }
  }

  /** Restore the inherited env and delete the shim directory. */
  async function dematerialize(run) {
    if (run?.bin !== undefined && process.env.PATH === `${run.bin}:${basePath}`) process.env.PATH = basePath
    if (baseAskpass === undefined) {
      if (run?.askpass !== undefined && process.env.SUDO_ASKPASS === run.askpass) delete process.env.SUDO_ASKPASS
    } else if (run?.askpass !== undefined && process.env.SUDO_ASKPASS === run.askpass) {
      process.env.SUDO_ASKPASS = baseAskpass
    }
    if (run?.root === undefined) return
    installed.delete(run.root)
    await rm(run.root, { recursive: true, force: true }).catch(() => {})
  }

  /** Synchronous last-resort cleanup for process exit and plugin unload. */
  function hardCleanup() {
    process.env.PATH = basePath
    if (baseAskpass === undefined) delete process.env.SUDO_ASKPASS
    else process.env.SUDO_ASKPASS = baseAskpass
    for (const root of installed) {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        // ignore
      }
    }
    installed.clear()
  }

  /**
   * Validate a password with one non-interactive `sudo -S -v` attempt.
   *
   * `-k` matters: `sudo -v` honours the timestamp cache, so within 15 minutes of
   * any earlier successful sudo it exits 0 without ever looking at the password.
   * Invalidating first forces a real PAM authentication, so a wrong password can
   * never be accepted just because a timestamp happened to be warm.
   * @param secret - the candidate password.
   * @returns whether sudo accepted it.
   */
  function validatePassword(secret) {
    return new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(value)
      }
      let child
      try {
        child = spawn(realSudo, ['-k', '-S', '-v'], {
          stdio: ['pipe', 'ignore', 'ignore'],
          env: {
            PATH: basePath,
            HOME: process.env.HOME ?? '',
            USER: process.env.USER ?? '',
            LOGNAME: process.env.LOGNAME ?? process.env.USER ?? '',
            SHELL: process.env.SHELL ?? '/bin/sh',
            TERM: 'dumb',
            LANG: 'C',
            LC_ALL: 'C',
          },
        })
      } catch {
        finish(false)
        return
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        finish(false)
      }, 20_000)
      child.on('error', () => finish(false))
      child.on('close', (code) => finish(code === 0))
      child.stdin.on('error', () => {})
      child.stdin.end(`${secret}\n`)
    })
  }

  // ------------------------------------------------------- pre-execute ----
  /** Whether this agent is a top-level agent (not a subagent or teammate). */
  function isRootAgent(agent) {
    const agents = ctx.get('agents')
    if (agents === undefined || typeof agents.roots !== 'function') return false
    try {
      return agents.roots().some((root) => root.id === agent.id)
    } catch {
      return false
    }
  }

  /** The sandbox mode this call would run under, when the deployment confines. */
  function sandboxModeOf(agent) {
    const policy = ctx.get('sandboxPolicy')
    if (policy === undefined || typeof policy.resolve !== 'function') return undefined
    try {
      const session = agent.session
      return policy.resolve(session === undefined ? {} : { session }).mode
    } catch {
      return undefined
    }
  }

  /** Ask the page and resolve the whole gate for one sudo command. */
  async function askForApproval(exec, analysis) {
    let session
    let cwd
    try {
      session = exec.agent.session
      cwd = typeof session?.cwd === 'string' ? session.cwd : undefined
    } catch {
      cwd = undefined
    }
    const request = {
      id: randomUUID(),
      callId: exec.callId,
      sessionId: exec.agent.id,
      createdAt: Date.now(),
      expiresAt: Date.now() + config.timeoutMs,
      cwd,
      items: analysis.items,
      settle: undefined,
      resolving: false,
    }
    inflight = request
    audit({ event: 'request', id: request.id, sessionId: request.sessionId, callId: request.callId, lines: analysis.items.length, cwd })
    const decision = await new Promise((resolve) => {
      let finished = false
      const finish = (value) => {
        if (finished) return
        finished = true
        clearTimeout(timer)
        exec.signal?.removeEventListener('abort', onAbort)
        resolve(value)
      }
      const timer = setTimeout(() => finish({ kind: 'timeout' }), config.timeoutMs)
      const onAbort = () => finish({ kind: 'cancelled' })
      request.settle = finish
      if (exec.signal?.aborted === true) {
        finish({ kind: 'cancelled' })
        return
      }
      exec.signal?.addEventListener('abort', onAbort, { once: true })
    }).finally(() => {
      if (inflight === request) inflight = undefined
    })
    return { request, decision }
  }

  /** Decide one sudo-bearing bash call. */
  async function decide(exec, analysis) {
    if (exec.agent === undefined) return { kind: 'deny', reason: MESSAGES.noAgent }
    if (exec.parent !== undefined) return { kind: 'deny', reason: MESSAGES.nested }
    if (isPlainObject(exec.arguments) && exec.arguments.run_in_background === true) {
      return { kind: 'deny', reason: MESSAGES.background }
    }
    if (!isRootAgent(exec.agent)) return { kind: 'deny', reason: MESSAGES.subagent }
    const mode = sandboxModeOf(exec.agent)
    if (mode !== undefined && mode !== 'danger-full-access') {
      audit({ event: 'denied', reason: 'sandbox', mode, sessionId: exec.agent.id })
      return { kind: 'deny', reason: MESSAGES.sandbox(mode) }
    }
    if (!config.allowRemoteDeployment) {
      const connection = ctx.get('connection')
      if (connection?.allowsRemoteAuthorities === true) {
        audit({ event: 'denied', reason: 'remote-deployment', sessionId: exec.agent.id })
        return { kind: 'deny', reason: MESSAGES.remote }
      }
    }
    if (inflight !== undefined || armed.size > 0) return { kind: 'deny', reason: MESSAGES.busy }
    if (lastPollAt === 0 || Date.now() - lastPollAt > config.presenceWindowMs) {
      audit({ event: 'denied', reason: 'no-client', sessionId: exec.agent.id })
      return { kind: 'deny', reason: MESSAGES.noClient }
    }

    const { request, decision } = await askForApproval(exec, analysis)
    if (decision.kind === 'approved' && typeof decision.secret === 'string' && decision.secret !== '') {
      armed.set(exec.callId, { secret: decision.secret, at: Date.now() })
      audit({ event: 'approved', id: request.id, sessionId: request.sessionId, callId: request.callId })
      return undefined
    }
    if (decision.kind === 'rejected') {
      audit({ event: 'rejected', id: request.id, sessionId: request.sessionId, reason: decision.reason })
      return { kind: 'deny', reason: MESSAGES.rejected(decision.reason) }
    }
    if (decision.kind === 'cancelled') {
      audit({ event: 'cancelled', id: request.id, sessionId: request.sessionId })
      return { kind: 'cancel' }
    }
    audit({ event: 'timeout', id: request.id, sessionId: request.sessionId })
    return { kind: 'deny', reason: MESSAGES.timeout(Math.round(config.timeoutMs / 1000)) }
  }

  /** Gate one tool call; returns a decision or undefined to dispatch. */
  async function gate(exec) {
    if (!config.enabled) return undefined
    if (typeof exec.name !== 'string' || !config.toolNames.has(exec.name)) return undefined
    const args = exec.arguments
    if (!isPlainObject(args) || typeof args.command !== 'string' || args.command === '') return undefined
    const analysis = analyzeCommand(args.command)
    if (!analysis.hasSudo) return undefined
    return decide(exec, analysis)
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    let verdict
    try {
      verdict = await gate(exec)
    } catch (error) {
      audit({ event: 'gate-error', message: errorText(error) })
      return { kind: 'deny', reason: MESSAGES.internal(errorText(error)) }
    }
    if (verdict !== undefined) return verdict
    return next()
  })

  // ----------------------------------------------------------- execute ----
  ctx.on('tools/execute', async (exec, next) => {
    const entry = armed.get(exec.callId)
    if (entry === undefined) return next()
    armed.delete(exec.callId)
    let run
    try {
      run = await materialize(entry.secret)
    } catch (error) {
      audit({ event: 'shim-error', callId: exec.callId, message: errorText(error) })
      return next()
    }
    audit({ event: 'execute', callId: exec.callId })
    try {
      return await next()
    } finally {
      await dematerialize(run)
      audit({ event: 'finished', callId: exec.callId })
    }
  })

  // ------------------------------------------------------------- routes ---
  /** Value the page polls for. */
  function snapshot() {
    if (inflight === undefined) return { requests: [] }
    const { id, sessionId, createdAt, expiresAt, cwd, items } = inflight
    const memo = config.remember === 'session' ? remembered.get(sessionId) : undefined
    return { requests: [{ id, sessionId, createdAt, expiresAt, cwd, items, passwordRequired: memo === undefined }] }
  }

  const respondJson = (payload, status = 200) =>
    Response.json(payload, { status, headers: { 'cache-control': 'no-store' } })

  /** Answer the page's approve/reject click. */
  async function respond(body) {
    const id = typeof body?.id === 'string' ? body.id : undefined
    const decision = body?.decision === 'approve' || body?.decision === 'reject' ? body.decision : undefined
    if (id === undefined || decision === undefined) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'id and decision are required' } }, 400)
    }
    const request = inflight
    if (request === undefined || request.id !== id) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/stale', message: 'this request is no longer pending' } }, 409)
    }
    if (request.resolving) {
      return respondJson({ ok: false, error: { code: 'sudo-approve/busy', message: 'this request is being resolved' } }, 409)
    }
    if (decision === 'reject') {
      request.settle?.({ kind: 'rejected', reason: normalizeReason(body?.reason) })
      return respondJson({ ok: true, value: { state: 'rejected' } })
    }
    request.resolving = true
    try {
      let secret = typeof body?.password === 'string' && body.password !== '' ? body.password : undefined
      if (secret === undefined && config.remember === 'session') {
        const memo = remembered.get(request.sessionId)
        if (memo !== undefined) secret = memo.secret
      }
      if (secret === undefined) {
        return respondJson({ ok: false, error: { code: 'sudo-approve/password-required', message: 'password is required' } }, 400)
      }
      if (!(await validatePassword(secret))) {
        audit({ event: 'invalid-password', id: request.id, sessionId: request.sessionId })
        return respondJson({ ok: false, error: { code: 'sudo-approve/invalid-password', message: MESSAGES.invalidPassword } }, 403)
      }
      if (config.remember === 'session') remembered.set(request.sessionId, { secret, usedAt: Date.now() })
      request.settle?.({ kind: 'approved', secret })
      return respondJson({ ok: true, value: { state: 'approved' } })
    } finally {
      request.resolving = false
    }
  }

  ctx.effect(() => {
    const scope = ctx.inject(['connection'], (child) => {
      const connection = child.get('connection')
      if (connection === undefined) return
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/pending`,
        methods: ['GET'],
        requestBody: 'buffered',
        fetch: async () => {
          lastPollAt = Date.now()
          return respondJson({ ok: true, value: snapshot() })
        },
      })
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/respond`,
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          lastPollAt = Date.now()
          let body
          try {
            body = await request.json()
          } catch {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'body is not JSON' } }, 400)
          }
          return respond(body)
        },
      })
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/config`,
        methods: ['GET', 'POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          // Deliberately does not refresh the presence window: a settings page
          // is not an approval surface.
          if (request.method !== 'POST') return respondJson({ ok: true, value: settingsSnapshot() })
          let body
          try {
            body = await request.json()
          } catch {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'body is not JSON' } }, 400)
          }
          if (body?.reset === true) {
            resetOverrides()
            audit({ event: 'configured', reset: true })
            return respondJson({ ok: true, value: settingsSnapshot() })
          }
          const patch = sanitizePatch(body?.patch)
          if (Object.keys(patch).length === 0) {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'no editable setting' } }, 400)
          }
          try {
            saveOverrides(patch)
          } catch (error) {
            return respondJson({ ok: false, error: { code: 'sudo-approve/store-failed', message: errorText(error) } }, 500)
          }
          audit({ event: 'configured', ...patch })
          return respondJson({ ok: true, value: settingsSnapshot() })
        },
      })
    })
    return () => {
      scope?.dispose?.()
    }
  }, `${NAME}: routes`)

  // ---------------------------------------------------------- lifecycle ---
  // A disposed session drops its remembered password.
  ctx.on('session/disposed', (session) => {
    remembered.delete(session?.id)
  })

  ctx.effect(() => {
    const onExit = () => hardCleanup()
    process.on('exit', onExit)
    const timer = setInterval(() => {
      const now = Date.now()
      for (const [callId, entry] of armed) {
        if (now - entry.at > 60_000) armed.delete(callId)
      }
      for (const [sessionId, memo] of remembered) {
        if (now - memo.usedAt > config.memoryTtlMs) remembered.delete(sessionId)
      }
    }, 30_000)
    return () => {
      process.off('exit', onExit)
      clearInterval(timer)
      hardCleanup()
      inflight = undefined
      armed.clear()
      remembered.clear()
    }
  }, `${NAME}: lifecycle`)
}
