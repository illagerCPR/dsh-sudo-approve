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

import { AsyncLocalStorage } from 'node:async_hooks'
import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

/** Plugin identity used in route paths, log lines and dir prefixes. */
const NAME = 'dsh-sudo-approve'
/** Bumped whenever a change has to be confirmed as live in the running Host. */
const BUILD = 13
/** Exact Fetch routes the browser half calls. */
const ROUTE_PREFIX = '/api/sudo-approve'
/** Fallback PATH when the Host process has none. */
const FALLBACK_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
/** Bounds for the tunable config values. */
const LIMITS = {
  timeoutMs: [5_000, 900_000],
  presenceWindowMs: [2_000, 300_000],
  memoryTtlMs: [60_000, 24 * 60 * 60 * 1000],
}

/**
 * Candidates for the real sudo. Resolution is confined to root-owned locations
 * and re-validated after `realpath`, because the password is handed to whatever
 * binary this ends up naming: a writable directory on `PATH` must never be able
 * to answer that question.
 */
const SUDO_CANDIDATES = Object.freeze(['/usr/bin/sudo', '/bin/sudo'])
/** The same treatment for sudoedit, which the shim also shadows. */
const SUDOEDIT_CANDIDATES = Object.freeze(['/usr/bin/sudoedit', '/bin/sudoedit'])

/**
 * Generated `sudo` shim. It exists only while an approved command runs and only
 * adds `-A`; forms that sudo-rs refuses to combine with `-A` (`-k`, `-V`, `-h`)
 * are forwarded untouched. The askpass helper travels in the shim's own
 * environment instead of the Host's, so concurrent installs cannot take the
 * password source away from each other.
 */
const SUDO_SHIM = `#!/bin/sh
for arg do
  case "$arg" in
    -k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)
      exec "@SUDO@" "$@" ;;
  esac
done
SUDO_ASKPASS="@ASKPASS@" exec "@SUDO@" -A "$@"
`

/** The PTC presentation transport; a sub-dispatch carries its token as `parent`. */
const RUN_CODE_NAME = 'run_code'

/**
 * Time a nested request leaves untouched at the end of its program budget, so
 * validation and the command itself still fit after the panel closes.
 */
const PTC_RESERVE_MS = 10_000
/** Shortest wait a nested request will open the panel for. */
const MIN_PANEL_MS = 5_000
/**
 * How many requests may wait behind the one on screen. The page shows a single
 * panel, so extra requests queue: refusing them outright made a parallel sudo
 * call fail for no reason the user could see.
 */
const QUEUE_LIMIT = 4

/** Defaults; a `cordis.patch.yml` `config` object overrides them. */
const DEFAULTS = Object.freeze({
  /** Master switch. */
  enabled: true,
  /** `never` asks for the password every time; `session` reuses it in memory. */
  remember: 'never',
  /**
   * How the validated password reaches the command: `askpass` installs a shim
   * that adds `-A` for exactly one spawn, `timestamp` relies on the sudo
   * credential cache, and `auto` probes the cache and falls back to the shim.
   */
  credential: 'auto',
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
  /** Absolute path of the real sudo; empty means "resolve on a trusted path". */
  sudoPath: '',
})

/**
 * Model-facing refusal texts. The model receives these as the pre-execute
 * denial reason, so they are written for an agent that must react sensibly.
 */
const MESSAGES = Object.freeze({
  noAgent: 'sudo 审批：无法确定发起该调用的智能体会话，已拒绝执行。',
  subagent: 'sudo 审批：子智能体不能申请 sudo，只有主会话可以直接执行 sudo 命令。请让主会话运行该命令。',
  background: 'sudo 审批：不支持 run_in_background 的 sudo 调用，请改为前台执行（需要你在按钮上确认）。',
  sandbox: (mode) => `sudo 审批：当前会话处于 ${mode} 沙箱，沙箱内无法获取 root。请先把会话权限切换到 danger-full-access 再重试。`,
  remote: 'sudo 审批：本部署接受非回环地址的浏览器连接，插件拒绝在明文网络路径上接收密码（配置项 allowRemoteDeployment=false），已拒绝执行。',
  noClient: 'sudo 审批：当前没有已连接的浏览器页面可以弹出确认面板，已拒绝执行。请在页面打开后重试。',
  queueFull: (limit) => `sudo 审批：排在前面等待确认的请求已有 ${limit} 笔，队列已满，已拒绝执行。请等前面的请求处理完再发。`,
  budget: (seconds) => `sudo 审批：所处 run_code 程序的 ${seconds} 秒执行预算已不足以完成确认，已拒绝执行。请把 sudo 调用放到程序开头，或单独放进一个简短的程序重试（并行发起的 sudo 请改为串行）。`,
  budgetQueued: (seconds) => `sudo 审批：等它轮到面板时，所处 run_code 程序的 ${seconds} 秒执行预算已经用完，已拒绝执行。请把 sudo 调用放到程序开头，或单独放进一个简短的程序重试（并行发起的 sudo 请改为串行）。`,
  rejected: (reason) => (reason === undefined || reason === '' ? 'sudo 审批：用户拒绝执行该 sudo 命令。' : `sudo 审批：用户拒绝执行该 sudo 命令。拒绝理由：${reason}`),
  timeout: (seconds) => `sudo 审批：${seconds} 秒内没有收到确认，已拒绝执行。`,
  invalidPassword: 'sudo 审批：密码校验未通过。',
  internal: (detail) => `sudo 审批插件内部错误，已拒绝执行：${detail}`,
  /** The panel may not show everything, so it refuses instead of hiding a tail. */
  truncated: (lines, width) =>
    `sudo 审批：该命令超出面板可完整显示的长度（最多 ${lines} 行、单行 ${width} 字符），为避免你批准看不见的内容，已拒绝执行。请把命令拆成更短的几条分别执行；不要把需要授权的内容藏进脚本文件再调用——那样面板同样看不到它。`,
  /** The approval record does not describe the call that is about to run. */
  mismatch: 'sudo 审批：批准记录与本次调用不匹配（会话、调用或命令内容已变化），已拒绝执行。请重新发起一次 sudo 调用。',
  /** `credential: timestamp` was configured but the cache cannot be reused here. */
  credential:
    'sudo 审批：配置要求用 sudo 时间戳缓存交付密码，但本机的 sudo 缓存无法被后续命令复用（无 tty 时按 tty/session 记账），已拒绝执行。请把 credential 改回 auto 或 askpass。',
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

/**
 * The only settings the page may change. They decide timing, not authority, so
 * a script holding a session cookie can move them without gaining anything but
 * a wider window; everything that decides what the gate does stays file-only.
 * `sanitizeRuntimePatch` below and the reset both have to agree with this list.
 */
const PAGE_EDITABLE_KEYS = Object.freeze(['timeoutMs', 'presenceWindowMs'])

/**
 * Keep only well-typed values from the settings file. Security-relevant keys
 * are accepted here on purpose: the file is the documented way to change them,
 * while the HTTP route below deliberately cannot.
 */
function sanitizePatch(raw) {
  const patch = {}
  if (!isPlainObject(raw)) return patch
  if (typeof raw.enabled === 'boolean') patch.enabled = raw.enabled
  if (raw.remember === 'never' || raw.remember === 'session') patch.remember = raw.remember
  if (raw.credential === 'auto' || raw.credential === 'askpass' || raw.credential === 'timestamp') {
    patch.credential = raw.credential
  }
  if (typeof raw.sudoPath === 'string' && raw.sudoPath !== '') patch.sudoPath = raw.sudoPath
  if (typeof raw.timeoutMs === 'number' && Number.isFinite(raw.timeoutMs)) patch.timeoutMs = Math.round(raw.timeoutMs)
  if (typeof raw.presenceWindowMs === 'number' && Number.isFinite(raw.presenceWindowMs)) {
    patch.presenceWindowMs = Math.round(raw.presenceWindowMs)
  }
  if (typeof raw.allowRemoteDeployment === 'boolean') patch.allowRemoteDeployment = raw.allowRemoteDeployment
  return patch
}

/**
 * The subset the browser may change. `enabled`, `remember`, `credential`,
 * `allowRemoteDeployment` and `sudoPath` decide what the gate does, so a page
 * (or any script running in it) must not be able to flip them: they stay
 * file-only.
 */
function sanitizeRuntimePatch(raw) {
  const patch = {}
  if (!isPlainObject(raw)) return patch
  if (typeof raw.timeoutMs === 'number' && Number.isFinite(raw.timeoutMs)) patch.timeoutMs = Math.round(raw.timeoutMs)
  if (typeof raw.presenceWindowMs === 'number' && Number.isFinite(raw.presenceWindowMs)) {
    patch.presenceWindowMs = Math.round(raw.presenceWindowMs)
  }
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
    credential: input.credential === 'askpass' || input.credential === 'timestamp' ? input.credential : 'auto',
    timeoutMs: clamp(input.timeoutMs, LIMITS.timeoutMs, DEFAULTS.timeoutMs),
    presenceWindowMs: clamp(input.presenceWindowMs, LIMITS.presenceWindowMs, DEFAULTS.presenceWindowMs),
    memoryTtlMs: clamp(input.memoryTtlMs, LIMITS.memoryTtlMs, DEFAULTS.memoryTtlMs),
    toolNames: new Set(toolNames.length > 0 ? toolNames : [...DEFAULTS.toolNames]),
    allowRemoteDeployment: input.allowRemoteDeployment === true,
    sudoPath: typeof input.sudoPath === 'string' ? input.sudoPath : '',
  }
}

/**
 * The `sudo` / `sudoedit` word, wherever it appears. Detection is fail-closed on
 * purpose: an absolute path (`/usr/bin/sudo`), a wrapper (`exec`, `env`,
 * `xargs`, `timeout`), or a quoted `bash -c "sudo …"` all reach the real
 * binary, so requiring a command word position under-detects and would let a
 * command run without the password panel.
 */
const SUDO_TOKEN = /(?:^|[^\w-])(?:sudo|sudoedit)(?=$|[^\w-])/

/** Forms that never authenticate, so they must not be given `-A`. */
const METADATA_ONLY_SUDO =
  /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s;&|()]*)\s+)*(?:sudo|sudoedit)\s+(?:-k|-K|-V|-h|--reset-timestamp|--remove-timestamp|--version|--help)\s*;?\s*$/

/** Cap on displayed command lines; a longer script is truncated in the panel. */
const MAX_DISPLAY_LINES = 60
/** Cap on one displayed line. */
const MAX_DISPLAY_WIDTH = 400

/**
 * Remove shell line continuations.
 *
 * A backslash before a newline is deleted before the line is split into words,
 * so `su\` + newline + `do` runs `sudo` while the raw text never contains the
 * word. Folding first is what makes the scan and the panel describe the command
 * bash will actually parse. Folding is deliberately over-eager: a backslash
 * inside single quotes stays literal for the shell, and folding it anyway can
 * only add a panel, never remove one.
 * @param text - the raw command string.
 * @returns the same command with continuations folded away.
 */
function foldContinuations(text) {
  return text.replace(/\\\r?\n/g, '')
}

/**
 * Turn a bash command into the lines the panel lists.
 *
 * `truncated` is a security fact, not a display detail: an approval covers the
 * whole command string, so a command the panel cannot show in full must never
 * be approved — the caller refuses it instead.
 * @param command - the tool's `command` argument.
 * @returns the displayed items, whether any of them needs real authority,
 *   whether the word appears at all, and whether the panel would hide part of
 *   the command.
 */
function analyzeCommand(command) {
  // Folding before splitting means the panel lists the text bash will parse.
  const folded = foldContinuations(command)
  const items = []
  let truncated = false
  for (const raw of folded.split(/\r?\n/)) {
    const text = raw.trim()
    if (text === '') continue
    if (items.length >= MAX_DISPLAY_LINES) {
      truncated = true
      break
    }
    // A whole-line shell comment can never execute, so it never asks.
    const sudo = !text.startsWith('#') && SUDO_TOKEN.test(text)
    if (text.length > MAX_DISPLAY_WIDTH) truncated = true
    items.push({
      text: text.length > MAX_DISPLAY_WIDTH ? `${text.slice(0, MAX_DISPLAY_WIDTH)}…` : text,
      sudo,
      // `sudo -k` / `sudo -V` never authenticate, so they need no password.
      privileged: sudo && !METADATA_ONLY_SUDO.test(text),
    })
  }
  if (truncated) items.push({ text: `…（仅显示前 ${MAX_DISPLAY_LINES} 行 / 每行 ${MAX_DISPLAY_WIDTH} 字符）`, sudo: false, privileged: false, note: true })
  return {
    items,
    hasSudo: items.some((item) => item.privileged),
    // Whether the word appears at all is a separate question from whether it
    // needs authority: it may sit in a comment, or in a `-k` form.
    mentionsSudo: SUDO_TOKEN.test(folded),
    truncated,
    digest: digestOf(command),
  }
}

/** Stable short fingerprint of a command string, for the audit log and `armed`. */
function digestOf(command) {
  return createHash('sha256').update(command, 'utf8').digest('hex').slice(0, 16)
}

/**
 * Find the real sudo on a trusted path.
 *
 * `sudo` is normally a symlink (`/usr/bin/sudo -> /etc/alternatives/sudo`), so
 * the link target is what runs and what must be root-owned and not group- or
 * world-writable. A config `sudoPath` overrides the candidates but is checked
 * the same way; anything that fails validation leaves the plugin inactive.
 * @param configured - a config-supplied absolute path, if any.
 * @param candidates - fallback list, already absolute.
 * @returns `{ path }` for the real binary, or undefined.
 */
function resolveTrusted(configured, candidates) {
  const list = configured === '' ? candidates : [configured, ...candidates]
  for (const candidate of list) {
    try {
      const real = realpathSync(candidate)
      const stat = statSync(real)
      if (!stat.isFile()) continue
      if (stat.uid !== 0) continue
      if ((stat.mode & 0o022) !== 0) continue
      return { path: real, link: candidate }
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
  const realSudo = resolveTrusted(config.sudoPath, SUDO_CANDIDATES)
  const realSudoedit = resolveTrusted('', SUDOEDIT_CANDIDATES)

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
    audit({ event: 'inactive', reason: 'sudo-not-trusted' })
    return
  }

  /** The one request currently waiting for the page, if any. */
  let inflight
  /** Requests waiting for their turn, oldest first; `inflight` is not in here. */
  const queue = []
  /** `${sessionId}:${callId}` → validated secret for one dispatch. */
  const armed = new Map()
  /** sessionId → { secret, usedAt } in `remember` mode. */
  const remembered = new Map()
  /** Timestamp of the last page poll; 0 means no page has ever polled. */
  let lastPollAt = 0
  /** Timestamp of the last poll from a *visible* page. */
  let lastVisibleAt = 0
  /** Timestamp of the last real user gesture reported by the page. */
  let lastInteractionAt = 0
  /**
   * Live shim installs. A shim never touches `process.env`: it is handed to one
   * spawn only, through `spec.env`, so an approved command cannot lend its
   * password to a concurrent session, subagent or background job.
   */
  const approvalScope = new AsyncLocalStorage()
  /**
   * `run_code` token → the moment its dispatch started. A program's elapsed
   * budget is fixed at that point, so this is what lets a nested request size
   * its panel inside the time that is actually left.
   */
  const ptcParents = new Map()

  audit({
    event: 'loaded',
    build: BUILD,
    remember: config.remember,
    credential: config.credential,
    timeoutMs: config.timeoutMs,
    sudo: realSudo.path,
  })

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

  /**
   * Drop the saved values the page is allowed to change; keep the rest.
   *
   * A reset that deleted the whole store used to hand the page a way around the
   * file-only rule: it could not POST `enabled:false`, but it could delete a
   * file that said `enabled:false` and fall back to the install-time value. The
   * two timing knobs belong to the page, so only they go.
   * @returns the keys that survived, so the audit line can name them.
   */
  function resetOverrides() {
    const next = { ...overrides }
    for (const key of PAGE_EDITABLE_KEYS) delete next[key]
    try {
      if (Object.keys(next).length === 0) rmSync(storePath, { force: true })
      else writeFileSync(storePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 })
    } catch {
      // best effort: the in-memory reset still applies
    }
    applyOverrides(next)
    return Object.keys(next)
  }

  /** Values and bounds the settings page renders. */
  function settingsSnapshot() {
    return {
      build: BUILD,
      store: storePath,
      auditLog,
      limits: { timeoutMs: LIMITS.timeoutMs, presenceWindowMs: LIMITS.presenceWindowMs },
      /** Keys the page shows but cannot change; edit the config or the store. */
      readOnly: ['enabled', 'remember', 'credential', 'allowRemoteDeployment', 'sudoPath'],
      values: {
        enabled: config.enabled,
        remember: config.remember,
        credential: config.credential,
        timeoutMs: config.timeoutMs,
        presenceWindowMs: config.presenceWindowMs,
        allowRemoteDeployment: config.allowRemoteDeployment,
      },
      sudo: realSudo.path,
      install: sanitizePatch(installConfig),
      overrides: { ...overrides },
    }
  }

  // ------------------------------------------------------------- env ------
  /** Shim installs that still own a directory; cleaned on unload or exit. */
  const liveRuns = new Set()
  /**
   * Installs that had to fall back to a process-wide `PATH` because the shell
   * service refused to be wrapped. Kept so the fallback can still be undone.
   */
  const globalRuns = []
  /** Whether the shim is delivered per spawn instead of through `process.env`. */
  let scopedShims = false

  /** Rebuild the process-wide PATH from the fallback installs, oldest last. */
  function syncGlobalPath() {
    process.env.PATH = globalRuns.length === 0 ? basePath : `${globalRuns.map((run) => run.bin).join(':')}:${basePath}`
  }

  /** The restricted environment `sudo` itself is invoked with. */
  function sudoEnv() {
    return {
      PATH: basePath,
      HOME: process.env.HOME ?? '',
      USER: process.env.USER ?? '',
      LOGNAME: process.env.LOGNAME ?? process.env.USER ?? '',
      SHELL: process.env.SHELL ?? '/bin/sh',
      TERM: 'dumb',
      LANG: 'C',
      LC_ALL: 'C',
    }
  }

  /**
   * Put one PATH shim and askpass helper in a private directory.
   *
   * Nothing global is mutated when scoped delivery is available: the directory
   * is named only in the `PATH` of the one spawn it was built for, so the
   * password cannot leak into a concurrent session, subagent or background job.
   */
  async function materialize(secret) {
    const root = await mkdtemp(join(process.env.XDG_RUNTIME_DIR || tmpdir(), `${NAME}-`))
    const run = { root }
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
      const shim = (target) => SUDO_SHIM.replaceAll('@SUDO@', target).replaceAll('@ASKPASS@', askpass)
      await writeFile(join(bin, 'sudo'), shim(realSudo.path), { mode: 0o700 })
      await chmod(join(bin, 'sudo'), 0o700)
      if (realSudoedit !== undefined) {
        await writeFile(join(bin, 'sudoedit'), shim(realSudoedit.path), { mode: 0o700 })
        await chmod(join(bin, 'sudoedit'), 0o700)
      }
      run.bin = bin
      run.askpass = askpass
      liveRuns.add(run)
      if (!scopedShims) {
        // Degraded: the shell service could not be wrapped, so the shim has to
        // ride the process environment. Audited so the difference is visible.
        globalRuns.push(run)
        syncGlobalPath()
      }
      return run
    } catch (error) {
      await dematerialize(run)
      throw error
    }
  }

  /** Delete one shim directory and forget it. */
  async function dematerialize(run) {
    if (run === undefined) return
    liveRuns.delete(run)
    const index = globalRuns.indexOf(run)
    if (index >= 0) {
      globalRuns.splice(index, 1)
      syncGlobalPath()
    }
    if (run.root === undefined) return
    await rm(run.root, { recursive: true, force: true }).catch(() => {})
  }

  /** Synchronous last-resort cleanup for process exit and plugin unload. */
  function hardCleanup() {
    const runs = [...liveRuns]
    liveRuns.clear()
    globalRuns.length = 0
    syncGlobalPath()
    for (const run of runs) {
      try {
        rmSync(run.root, { recursive: true, force: true })
      } catch {
        // ignore
      }
    }
  }

  /**
   * Delete shim directories a crashed Host left behind. They hold a plaintext
   * password, so a stale one must not survive the next start; the age guard
   * keeps a concurrently starting Host's fresh directory untouched.
   */
  function sweepStaleRuns() {
    const parent = process.env.XDG_RUNTIME_DIR || tmpdir()
    let entries
    try {
      entries = readdirSync(parent)
    } catch {
      return
    }
    for (const entry of entries) {
      if (!entry.startsWith(`${NAME}-`)) continue
      const target = join(parent, entry)
      try {
        const stat = statSync(target)
        if (!stat.isDirectory()) continue
        if (Date.now() - stat.mtimeMs < 60_000) continue
        rmSync(target, { recursive: true, force: true })
        audit({ event: 'stale-cleanup', path: target })
      } catch {
        // best effort
      }
    }
  }

  /**
   * Teach the shell service to deliver a shim to one spawn.
   *
   * The bash tool asks `ctx.shell.resolve()` for a fully specified spec and then
   * spawns it with `spec.env`; wrapping `resolve` therefore lets this plugin put
   * its `PATH` on exactly the spawn the user approved. The approval travels in
   * an AsyncLocalStorage store set by the `tools/execute` hook, which is what
   * keeps two concurrent approvals from seeing each other's shim.
   */
  ctx.effect(() => {
    let restore
    const scope = ctx.inject(['shell'], (child) => {
      const service = child.get('shell')
      if (service === undefined || typeof service.resolve !== 'function') return
      const original = service.resolve
      /** Counts calls that reached the wrapper; identity cannot be used, see below. */
      const hits = { count: 0 }
      const patched = function resolve(request) {
        hits.count += 1
        const spec = original.call(service, request)
        const run = approvalScope.getStore()
        if (run === undefined || typeof run.bin !== 'string') return spec
        const inherited = isPlainObject(spec.env) && typeof spec.env.PATH === 'string' ? spec.env.PATH : basePath
        return {
          ...spec,
          env: { ...(isPlainObject(spec.env) ? spec.env : {}), PATH: `${run.bin}:${inherited}` },
        }
      }
      /**
       * Whether the write actually reaches callers. Cordis hands out a fresh
       * proxy for every method read (per-context shadowing), so comparing
       * `service.resolve` against `patched` always reports a mismatch even when
       * the assignment worked — the wrapper has to be observed instead. The
       * probe only builds a spec; nothing is spawned.
       */
      const reaches = () => {
        const before = hits.count
        try {
          service.resolve({ command: 'true', workdir: process.cwd() })
        } catch {
          return false
        }
        return hits.count > before
      }

      try {
        service.resolve = patched
        if (!reaches()) throw new Error('service instance refused the write')
        scopedShims = true
        restore = () => {
          try {
            delete service.resolve
          } catch {
            service.resolve = original
          }
          scopedShims = false
        }
        audit({ event: 'shim-scope', mode: 'instance' })
        return
      } catch {
        // Fall through: patch the class method instead of the instance.
      }

      try {
        const proto = Object.getPrototypeOf(service)
        if (proto === null || typeof proto.resolve !== 'function') throw new Error('no writable resolve on the prototype')
        const previous = proto.resolve
        proto.resolve = patched
        if (!reaches()) {
          proto.resolve = previous
          throw new Error('prototype refused the write')
        }
        scopedShims = true
        restore = () => {
          proto.resolve = previous
          scopedShims = false
        }
        audit({ event: 'shim-scope', mode: 'prototype' })
      } catch (error) {
        audit({ event: 'shim-global', reason: 'shell-not-wrappable', message: errorText(error) })
      }
    })
    return () => {
      restore?.()
      scope?.dispose?.()
    }
  }, `${NAME}: scoped shim`)

  sweepStaleRuns()

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
        child = spawn(realSudo.path, ['-k', '-S', '-v'], {
          stdio: ['pipe', 'ignore', 'ignore'],
          env: sudoEnv(),
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

  /** Run one non-interactive sudo probe; resolves with its exit status. */
  function probeSudo(args, timeoutMs) {
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
        child = spawn(realSudo.path, args, { stdio: ['ignore', 'ignore', 'ignore'], env: sudoEnv() })
      } catch {
        finish(false)
        return
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        finish(false)
      }, timeoutMs)
      child.on('error', () => finish(false))
      child.on('close', (code) => finish(code === 0))
    })
  }

  /**
   * Whether the credential cache a validated password leaves behind can be
   * reused by the command itself.
   *
   * It cannot on a default `timestamp_type=tty` setup: the validation runs with
   * no controlling terminal, so the record is filed under a key the command's
   * own (equally tty-less) sudo does not look up. A false answer is normal and
   * is what sends `auto` to the askpass shim; a true answer means no shim and no
   * password file are needed at all.
   * @returns whether `sudo -n` already works without a password.
   */
  function timestampUsable() {
    return probeSudo(['-n', '-v'], 5_000)
  }

  /** Drop the invoking user's cached sudo credential; best effort. */
  function clearTimestamp() {
    return probeSudo(['-k'], 5_000)
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

  /** Whether this agent's model reaches tools through `run_code` (PTC presentation). */
  function presentsPtc(agent) {
    const tools = ctx.get('tools')
    if (tools === undefined || typeof tools.get !== 'function') return false
    try {
      // The transport is visible only to scopes whose mode actually presents it.
      return tools.get(RUN_CODE_NAME, agent) !== undefined
    } catch {
      return false
    }
  }

  /** The elapsed budget a `run_code` program runs with, when one is mounted. */
  function ptcBudgetMs() {
    try {
      const timeout = ctx.get('ptcRuntime')?.timeout
      return typeof timeout?.defaultMs === 'number' && timeout.defaultMs > 0 ? timeout.defaultMs : undefined
    } catch {
      return undefined
    }
  }

  /**
   * Size the wait of a nested (PTC) request inside what is left of its program.
   *
   * A `run_code` program's elapsed budget covers the approval wait and was fixed
   * when the program started. Waiting longer than the budget would kill the
   * program while the user is still typing, so the panel closes before that, and
   * a request with too little left is refused up front instead of opening a
   * panel nobody can finish in time.
   * @param exec - the nested call.
   * @returns `{ waitMs, deadlineAt }`, or `{ deny }` when no panel would fit.
   */
  function nestedPlan(exec) {
    const budget = ptcBudgetMs()
    if (budget === undefined) return { waitMs: config.timeoutMs }
    const startedAt = ptcParents.get(exec.parent)
    const deadlineAt = (startedAt === undefined ? Date.now() : startedAt) + budget - PTC_RESERVE_MS
    const left = deadlineAt - Date.now()
    if (left < MIN_PANEL_MS) return { deny: MESSAGES.budget(Math.round(budget / 1000)) }
    return { waitMs: Math.min(config.timeoutMs, Math.floor(left)), deadlineAt }
  }

  /** Whether a visible page has polled recently enough to show a panel. */
  function pagePresent() {
    const now = Date.now()
    if (lastPollAt === 0 || now - lastPollAt > config.presenceWindowMs) return false
    // A hidden tab keeps polling exactly like a visible one, so the page has to
    // report that it is on screen before it can be treated as somebody watching.
    return lastVisibleAt !== 0 && now - lastVisibleAt <= config.presenceWindowMs
  }

  /** Whether the page reported a real user gesture (click, key, focus) lately. */
  function interactionPresent() {
    return lastInteractionAt !== 0 && Date.now() - lastInteractionAt <= config.presenceWindowMs
  }

  /**
   * Approval key for one dispatch. A provider's `callId` is only unique within
   * its own conversation, so the session has to be part of the key: otherwise a
   * collision in another session would inherit this approval.
   */
  function armKey(exec) {
    return `${exec.agent === undefined ? '?' : exec.agent.id}:${exec.callId}`
  }

  /** Put one request on screen: fix its deadline, log it, start its timer. */
  function admit(request) {
    request.state = 'visible'
    request.startedAt = Date.now()
    if (request.deadlineAt !== undefined) {
      // It may have queued for a while, so re-measure instead of trusting the
      // wait computed when it arrived.
      request.waitMs = Math.max(MIN_PANEL_MS, Math.min(request.waitMs, Math.floor(request.deadlineAt - request.startedAt)))
    }
    request.expiresAt = request.startedAt + request.waitMs
    inflight = request
    audit({
      event: 'request',
      id: request.id,
      sessionId: request.sessionId,
      callId: request.callId,
      lines: request.items.length,
      waitMs: request.waitMs,
      ...(request.nested ? { channel: 'ptc' } : {}),
      ...(request.position > 1 ? { position: request.position } : {}),
      cwd: request.cwd,
    })
    request.start?.()
  }

  /**
   * Show the next queued request, skipping any that can no longer be answered:
   * the page has gone away, or a nested request's program budget no longer has
   * room for a panel at all. Skipping rather than opening a doomed panel keeps
   * the queue moving.
   */
  function pump() {
    if (inflight !== undefined) return
    while (queue.length > 0) {
      const next = queue[0]
      if (!pagePresent()) {
        queue.shift()
        next.settle?.({ kind: 'noClient' })
        continue
      }
      if (next.deadlineAt !== undefined && next.deadlineAt - Date.now() < MIN_PANEL_MS) {
        queue.shift()
        next.settle?.({ kind: 'budget' })
        continue
      }
      queue.shift()
      admit(next)
      return
    }
  }

  /**
   * Ask the page and resolve the whole gate for one sudo command.
   *
   * The page renders a single panel, so a second request waits in line instead
   * of being refused. Its own wait only starts when it reaches the screen; a
   * nested request additionally cannot outlive its program's budget, so it gives
   * up while still queued once no panel would fit.
   * @param exec - the tool call being gated.
   * @param analysis - the command analysis (lines to show).
   * @param plan - `{ waitMs, deadlineAt? }` from `nestedPlan`.
   */
  async function askForApproval(exec, analysis, plan) {
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
      cwd,
      items: analysis.items,
      nested: exec.parent !== undefined,
      waitMs: plan.waitMs,
      deadlineAt: plan.deadlineAt,
      expiresAt: undefined,
      state: 'queued',
      position: 1,
      settle: undefined,
      start: undefined,
      resolving: false,
    }
    const decided = new Promise((resolve) => {
      let finished = false
      let panelTimer
      let deadlineTimer
      const finish = (value) => {
        if (finished) return
        finished = true
        clearTimeout(panelTimer)
        clearTimeout(deadlineTimer)
        exec.signal?.removeEventListener('abort', onAbort)
        resolve(value)
      }
      const onAbort = () => finish({ kind: 'cancelled' })
      request.settle = finish
      request.start = () => {
        // On screen now: the panel's own wait (already clamped to the budget)
        // owns the deadline, so the queue guard must not fire first.
        clearTimeout(deadlineTimer)
        deadlineTimer = undefined
        panelTimer = setTimeout(() => finish({ kind: 'timeout' }), request.waitMs)
      }
      // A nested request that runs out of program budget while still queued must
      // give up here: by the time it reached the screen nothing could be typed.
      if (request.deadlineAt !== undefined) {
        const leave = Math.max(0, request.deadlineAt - MIN_PANEL_MS - Date.now())
        deadlineTimer = setTimeout(() => finish({ kind: 'budget' }), leave)
      }
      if (exec.signal?.aborted === true) {
        finish({ kind: 'cancelled' })
        return
      }
      exec.signal?.addEventListener('abort', onAbort, { once: true })
    }).finally(() => {
      const index = queue.indexOf(request)
      if (index >= 0) queue.splice(index, 1)
      if (inflight === request) inflight = undefined
      pump()
    })
    queue.push(request)
    pump()
    if (request.state === 'queued') {
      request.position = queue.indexOf(request) + 1
      audit({
        event: 'queued',
        id: request.id,
        sessionId: request.sessionId,
        callId: request.callId,
        lines: request.items.length,
        position: request.position,
      })
    }
    return { request, decision: await decided }
  }

  /** Decide one sudo-bearing bash call. */
  async function decide(exec, analysis) {
    if (exec.agent === undefined) return { kind: 'deny', reason: MESSAGES.noAgent }
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
    // The panel is one at a time, so parallel calls line up behind it. Only a
    // queue that is already full is refused, and it says so.
    if (queue.length >= QUEUE_LIMIT) {
      audit({ event: 'denied', reason: 'queue-full', sessionId: exec.agent.id, callId: exec.callId })
      return { kind: 'deny', reason: MESSAGES.queueFull(QUEUE_LIMIT) }
    }
    if (!pagePresent()) {
      audit({ event: 'denied', reason: 'no-client', sessionId: exec.agent.id })
      return { kind: 'deny', reason: MESSAGES.noClient }
    }
    // A PTC sub-dispatch is how that presentation reaches any tool, so it is a
    // normal path rather than a nested bypass: the password is still required.
    // What differs is the wait, which has to fit inside the program's budget.
    let plan = { waitMs: config.timeoutMs }
    if (exec.parent !== undefined) {
      plan = nestedPlan(exec)
      if (plan.deny !== undefined) {
        audit({ event: 'denied', reason: 'ptc-budget', sessionId: exec.agent.id, callId: exec.callId })
        return { kind: 'deny', reason: plan.deny }
      }
    }

    const { request, decision } = await askForApproval(exec, analysis, plan)
    if (decision.kind === 'approved' && typeof decision.secret === 'string' && decision.secret !== '') {
      armed.set(armKey(exec), {
        secret: decision.secret,
        at: Date.now(),
        sessionId: exec.agent.id,
        // The secret is released only to a dispatch whose command still hashes
        // to what the user was shown.
        digest: digestOf(typeof exec.arguments.command === 'string' ? exec.arguments.command : ''),
      })
      audit({
        event: 'approved',
        id: request.id,
        sessionId: request.sessionId,
        callId: request.callId,
        digest: analysis.digest,
        // A remembered secret was reused: no password was typed for this one.
        ...(decision.memo === true ? { memo: true } : {}),
      })
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
    if (decision.kind === 'budget') {
      audit({ event: 'denied', reason: 'ptc-budget', id: request.id, sessionId: request.sessionId, callId: request.callId, queued: true })
      return { kind: 'deny', reason: MESSAGES.budgetQueued(Math.round((ptcBudgetMs() ?? config.timeoutMs) / 1000)) }
    }
    if (decision.kind === 'noClient') {
      audit({ event: 'denied', reason: 'no-client', id: request.id, sessionId: request.sessionId, queued: true })
      return { kind: 'deny', reason: MESSAGES.noClient }
    }
    audit({ event: 'timeout', id: request.id, sessionId: request.sessionId })
    return { kind: 'deny', reason: MESSAGES.timeout(Math.round(request.waitMs / 1000)) }
  }

  /** Gate one tool call; returns a decision or undefined to dispatch. */
  async function gate(exec) {
    if (!config.enabled) return undefined
    if (typeof exec.name !== 'string' || !config.toolNames.has(exec.name)) return undefined
    const args = exec.arguments
    if (!isPlainObject(args) || typeof args.command !== 'string' || args.command === '') return undefined
    const analysis = analyzeCommand(args.command)
    // A sudo call can sit past the display cap, where the per-line scan cannot
    // see it, so the folded whole string is scanned before this command is
    // written off as needing no gate at all.
    if (!analysis.hasSudo && !analysis.mentionsSudo) return undefined
    // An approval covers the whole command string, so a command the panel could
    // not show in full is refused rather than approved blind.
    if (analysis.truncated) {
      audit({ event: 'denied', reason: 'truncated', sessionId: exec.agent.id, callId: exec.callId, digest: analysis.digest })
      return { kind: 'deny', reason: MESSAGES.truncated(MAX_DISPLAY_LINES, MAX_DISPLAY_WIDTH) }
    }
    // The token only appeared in comments or in a form that never authenticates.
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

  // ----------------------------------------------------------- context ----
  // The rules are the same whichever way the model reaches bash; only the
  // opening sentence (how to get to sudo at all) depends on the presentation.
  const SUDO_RULES = [
    'Write it plainly (`sudo <command>`) — the approved call authenticates by itself, so never pass a password, pipe one in, or add `-n`/`-S`/askpass flags; `sudo -n` always fails here.',
    'Keep the whole command short: the panel shows at most 60 lines and 400 characters per line, and a command that would not fit is refused outright instead of being approved blind — split it into several shorter commands. Do not move part of it into a script file and call that instead: a file the panel cannot show is a file the user never approved.',
    'One approval covers the whole command string, so keep sudo lines few and short. A rejection may quote the user\u2019s reason: do not retry the same command unchanged.',
    'Approvals are handled one at a time in arrival order: a parallel sudo call waits in line instead of failing, but each wait delays the command behind it, so keep sudo calls sequential and few. `sudo -k`, `-K`, `-V` and `-h` alone need no approval; sudo is unavailable in subagents and background jobs.',
  ].join(' ')

  /**
   * The runtime-context paragraph for a native presentation: sudo exists here,
   * the asking happens in the GUI, so the model should write plain sudo instead
   * of trying to authenticate by itself.
   */
  const SUDO_CONTEXT = [
    '`sudo` is available here: a foreground `bash` call that invokes `sudo` or `sudoedit` shows the user the command in the GUI and asks for their password before it runs.',
    SUDO_RULES,
  ].join(' ')

  /**
   * The paragraph for a PTC presentation, where reaching `bash` costs a nested
   * sub-dispatch and the approval wait is charged to the program budget. It
   * replaces the native opening sentence instead of preceding it: both describe
   * how to invoke sudo, and shipping both would hand the model two different
   * calling conventions at once.
   * @returns the paragraph for this deployment.
   */
  function ptcContext() {
    const budget = ptcBudgetMs()
    const span = budget === undefined ? 'fixed elapsed budget' : `${Math.round(budget / 1000)} second elapsed budget`
    return [
      '`sudo` is available here through `run_code`: a `tools.bash` call whose command invokes `sudo` or `sudoedit` shows the user the command in the GUI and asks for their password while the program waits.',
      `That wait, and the command itself, are charged to the program\u2019s ${span}, so put the sudo call near the start of a short program; a request whose program has too little time left is refused before any panel opens, or gives up while still waiting in line, and the answer is to rerun that sudo call in its own small program.`,
      SUDO_RULES,
    ].join(' ')
  }

  ctx.effect(() => {
    const scope = ctx.inject(['systemPrompt'], (child) => {
      const prompt = child.systemPrompt
      if (prompt === undefined || typeof prompt.context !== 'function') return
      const anchor = typeof prompt.getContextOrder === 'function' ? prompt.getContextOrder('APPROVAL_POLICY') : undefined
      prompt.context({
        name: `${NAME}:availability`,
        // Right after the approval-policy line it qualifies.
        order: Number.isFinite(anchor) ? anchor + 1 : 116,
        text: (context) => {
          const agent = context?.agent
          if (agent === undefined || !config.enabled) return ''
          // The gate only runs for the root agent in a full-access session.
          if (!isRootAgent(agent)) return ''
          const mode = sandboxModeOf(agent)
          if (mode !== undefined && mode !== 'danger-full-access') return ''
          // Both variants carry the shared rules; only the opening differs.
          return presentsPtc(agent) ? ptcContext() : SUDO_CONTEXT
        },
      })
    })
    return () => {
      scope?.dispose?.()
    }
  }, `${NAME}: context`)

  // ----------------------------------------------------------- execute ----
  /**
   * Hand one validated secret to exactly one dispatch.
   *
   * Two deliveries are possible. When the sudo credential cache is reusable the
   * command needs no help at all: it runs untouched and the cache is dropped
   * afterwards. Otherwise a shim is built for this dispatch and injected through
   * the spec of its spawn only, so no other process can inherit the password.
   *
   * Both paths drop the timestamp cache when they are done. That record is not a
   * detail of the delivery method: it is what lets a later `sudo` skip the
   * password entirely, so an approval must never leave one behind.
   * @param exec - the tool call being dispatched.
   * @param secret - the validated password.
   * @param next - the rest of the middleware chain.
   */
  async function dispatchWithSecret(exec, secret, next) {
    if (config.credential !== 'askpass' && (await timestampUsable())) {
      audit({ event: 'execute', callId: exec.callId, credential: 'timestamp' })
      try {
        return await next()
      } finally {
        await clearTimestamp()
        audit({ event: 'finished', callId: exec.callId })
      }
    }
    if (config.credential === 'timestamp') {
      audit({ event: 'denied', reason: 'credential-unavailable', callId: exec.callId })
      throw new Error(MESSAGES.credential)
    }
    let run
    try {
      run = await materialize(secret)
    } catch (error) {
      audit({ event: 'shim-error', callId: exec.callId, message: errorText(error) })
      return next()
    }
    audit({ event: 'execute', callId: exec.callId, credential: 'askpass', scoped: scopedShims })
    try {
      return await approvalScope.run(run, () => next())
    } finally {
      await dematerialize(run)
      // The approved command's own `sudo -A` authenticates, and a successful
      // authentication writes a timestamp record. Drop it on this path too: the
      // record is what would turn one approval into a password-free window for
      // anything that can reuse its key, whatever `credential` was configured.
      await clearTimestamp()
      audit({ event: 'finished', callId: exec.callId })
    }
  }

  ctx.on('tools/execute', async (exec, next) => {
    // Time a PTC program from the moment its dispatch starts: its budget is
    // fixed here, and a nested sudo request later needs what is left of it.
    if (exec.name === RUN_CODE_NAME && exec.parent === undefined) {
      ptcParents.set(exec.token, Date.now())
      try {
        return await next()
      } finally {
        ptcParents.delete(exec.token)
      }
    }
    const key = armKey(exec)
    const entry = armed.get(key)
    if (entry === undefined) return next()
    armed.delete(key)
    const command = isPlainObject(exec.arguments) && typeof exec.arguments.command === 'string' ? exec.arguments.command : undefined
    if (entry.digest !== undefined && command !== undefined && digestOf(command) !== entry.digest) {
      audit({ event: 'armed-mismatch', callId: exec.callId, sessionId: entry.sessionId })
      throw new Error(MESSAGES.mismatch)
    }
    return dispatchWithSecret(exec, entry.secret, next)
  })

  // ------------------------------------------------------------- routes ---
  /**
   * Value the page polls for: the one request on screen plus how many are
   * waiting behind it, so the panel can say that a parallel call is in line.
   */
  function snapshot() {
    const waiting = queue.length
    if (inflight === undefined) return { requests: [], waiting }
    const { id, sessionId, createdAt, expiresAt, cwd, items } = inflight
    const memo = config.remember === 'session' ? remembered.get(sessionId) : undefined
    return { requests: [{ id, sessionId, createdAt, expiresAt, cwd, items, passwordRequired: memo === undefined }], waiting }
  }

  const respondJson = (payload, status = 200) =>
    Response.json(payload, { status, headers: { 'cache-control': 'no-store' } })

  /**
   * Record how the page presented itself on this request.
   *
   * `state=visible` and `interaction=1` are claims made by the page, so they are
   * a speed bump rather than a proof: they stop a hidden tab from counting as
   * somebody watching, and they let a gesture be reported before the approval
   * that leans on it. A script that holds a session cookie can assert both; that
   * is why the security-relevant switches are file-only.
   */
  function notePresence(request) {
    const now = Date.now()
    lastPollAt = now
    let url
    try {
      url = new URL(request.url)
    } catch {
      return
    }
    if (url.searchParams.get('state') === 'visible') lastVisibleAt = now
    if (url.searchParams.get('interaction') === '1') lastInteractionAt = now
  }

  /**
   * Answer the page's approve/reject click.
   * @param body - the JSON body.
   * @param gestured - whether a gesture was reported *before* this request was
   *   seen. It is read by the route before `notePresence` records the current
   *   request, because an approval that supplied its own evidence would be
   *   judged against a fact it had just written.
   */
  async function respond(body, gestured) {
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
    // An approval leans on a gesture reported before it, never on its own claim.
    if (body?.interaction !== true || gestured !== true) {
      audit({ event: 'denied', reason: 'no-interaction', id: request.id, sessionId: request.sessionId })
      return respondJson(
        { ok: false, error: { code: 'sudo-approve/no-interaction', message: 'approval requires a user gesture reported before it' } },
        403,
      )
    }
    request.resolving = true
    try {
      let secret = typeof body?.password === 'string' && body.password !== '' ? body.password : undefined
      let memo = false
      if (secret === undefined && config.remember === 'session') {
        const stored = remembered.get(request.sessionId)
        if (stored !== undefined) {
          secret = stored.secret
          memo = true
        }
      }
      if (secret === undefined) {
        return respondJson({ ok: false, error: { code: 'sudo-approve/password-required', message: 'password is required' } }, 400)
      }
      if (!(await validatePassword(secret))) {
        audit({ event: 'invalid-password', id: request.id, sessionId: request.sessionId })
        return respondJson({ ok: false, error: { code: 'sudo-approve/invalid-password', message: MESSAGES.invalidPassword } }, 403)
      }
      if (config.remember === 'session') remembered.set(request.sessionId, { secret, usedAt: Date.now() })
      request.settle?.({ kind: 'approved', secret, memo })
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
        fetch: async (request) => {
          notePresence(request)
          return respondJson({ ok: true, value: snapshot() })
        },
      })
      connection.fetch.register({
        path: `${ROUTE_PREFIX}/respond`,
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          // Read the gesture *before* this request records its own claim: an
          // approval must rest on evidence that existed when it arrived.
          const gestured = interactionPresent()
          notePresence(request)
          let body
          try {
            body = await request.json()
          } catch {
            return respondJson({ ok: false, error: { code: 'sudo-approve/bad-request', message: 'body is not JSON' } }, 400)
          }
          return respond(body, gestured)
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
            const kept = resetOverrides()
            audit({ event: 'configured', reset: true, ...(kept.length === 0 ? {} : { kept }) })
            return respondJson({ ok: true, value: settingsSnapshot() })
          }
          // Only the two timing knobs are page-editable; everything that
          // decides what the gate does is file-only by design.
          const patch = sanitizeRuntimePatch(body?.patch)
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
      // Unload either way: queued models must not wait for a panel that will
      // never come, so every waiter is settled before the state is dropped.
      for (const request of queue.splice(0, queue.length)) request.settle?.({ kind: 'cancelled' })
      inflight?.settle?.({ kind: 'cancelled' })
      inflight = undefined
      armed.clear()
      remembered.clear()
      ptcParents.clear()
    }
  }, `${NAME}: lifecycle`)
}
