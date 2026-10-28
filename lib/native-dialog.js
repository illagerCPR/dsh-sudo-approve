/**
 * The native approval dialog.
 *
 * In `native` mode the whole approval happens on the host display: the command,
 * a password field, and OK/Cancel live in one system dialog, and the Web page
 * plays no part in the decision. That is what makes the page's cookie worthless
 * for approval — a model holding a signed cookie can at most *cause* a dialog to
 * appear; it cannot press the button.
 *
 * Eligibility is sampled once per boot, exactly like the Harness directory
 * picker: a dialog nobody can see or reach is worse than falling back to the
 * page, so anything ambiguous resolves to the page.
 *
 * The backend binary is resolved on fixed root-owned paths (`lib/trusted`), never
 * through `PATH`: a program that asks for the login password must not be a
 * program that anything running as this user could have put there.
 *
 * Which dialog that binary is asked for matters: zenity's password dialog has no
 * text option, so `--password … --text …` silently shows no command at all. The
 * text is therefore rendered by the entry dialog with a masked input
 * (`--entry --hide-text`), and the options are verified against a screenshot of
 * the real binary rather than against its argv.
 * @module dsh-sudo-approve/lib/native-dialog
 */

import { spawn } from 'node:child_process'

import { resolveDialogBinary } from './trusted.js'

/**
 * Line cap for the dialog.
 *
 * A system dialog has no scrollbar, so text taller than the screen would hide
 * part of the command while still asking for approval — the one thing an
 * approval surface must never do. Native mode therefore refuses earlier than the
 * Web panel (60) rather than showing a clipped command.
 */
export const NATIVE_MAX_LINES = 24

/** Environment a dialog needs to reach the display; nothing else is passed. */
const DISPLAY_ENV = [
  'PATH',
  'HOME',
  'DISPLAY',
  'WAYLAND_DISPLAY',
  'XDG_RUNTIME_DIR',
  'XDG_SESSION_TYPE',
  'XAUTHORITY',
  'DBUS_SESSION_BUS_ADDRESS',
  'LANG',
  'LC_ALL',
]

/** An env value counts only when set and non-blank. */
const present = (value) => value !== undefined && value !== ''

/** Whether a configured bind address is loopback-only, using the Harness rule. */
function isLoopbackHost(host) {
  if (typeof host !== 'string' || host === '') return false
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  const text = bare.toLowerCase()
  if (text === 'localhost' || text === '::1') return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4 === null) return false
  const octets = v4.slice(1).map(Number)
  if (octets.some((part) => part > 255)) return false
  return octets[0] === 127
}

/**
 * Sample everything that decides whether a native dialog is possible here.
 *
 * The signals are the same ones the Harness uses for its own native surfaces: no
 * remote-authority trust, a loopback-only bind, not launched over SSH, a display
 * session, and a dialog binary. Each failure is reported by name so a forced
 * `native` can say exactly what is missing.
 * @param ctx - the plugin context.
 * @returns `{ eligible, missing, chooser }`.
 */
export function sampleDialogFacts(ctx) {
  const missing = []
  const connection = ctx.get('connection')
  if (connection?.allowsRemoteAuthorities === true) missing.push('remote-authority')
  const webServer = ctx.get('webServer')
  if (webServer?.host !== undefined && !isLoopbackHost(webServer.host)) missing.push('bind-address')
  // A forwarded connection cannot reach the operator's screen.
  if (present(process.env.SSH_CONNECTION) || present(process.env.SSH_TTY)) missing.push('ssh')
  const platform = process.platform
  if (platform !== 'linux' && platform !== 'darwin' && platform !== 'win32') missing.push('platform')
  if (platform === 'linux' && !present(process.env.DISPLAY) && !present(process.env.WAYLAND_DISPLAY)) {
    missing.push('display')
  }
  const chooser = resolveDialogBinary()
  if (chooser === undefined) missing.push('dialog-binary')
  return { eligible: missing.length === 0, missing, chooser }
}

/** Why a signal failed, in the words a refusal reason uses. */
const MISSING_TEXT = Object.freeze({
  'remote-authority': '本部署接受非回环地址的浏览器连接',
  'bind-address': '宿主没有绑定回环地址',
  ssh: '宿主是通过 SSH 启动的（对话框到不了操作者的屏幕）',
  display: '没有可用的图形会话（DISPLAY / WAYLAND_DISPLAY 皆空）',
  platform: '当前平台不支持原生对话框',
  'dialog-binary': '系统里没有可信的 zenity 或 kdialog（只认 root 所有、且所在目录不可被非 root 改写的 /usr/bin、/usr/local/bin）',
})

/**
 * Render the dialog body: the lines that will run, the code the page shows too,
 * and the digest for the log.
 *
 * The code is what lets the operator check that this window is the one the Host
 * opened for the request in the page — a window that asks for the password
 * without carrying the same code is not this plugin's.
 * @param analysis - the command analysis.
 * @param code - the cross-surface check code for this request.
 */
function dialogText(analysis, code) {
  const lines = analysis.items.map((item) => item.text).join('\n')
  return [
    `即将以 root 执行以下 ${analysis.items.length} 行命令：`,
    '',
    lines,
    '',
    `核对码 ${code}（须与网页上显示的核对码一致）`,
    `摘要 ${analysis.digest}（可对照 ~/.dsh/logs/dsh-sudo-approve.log）`,
    '密码只交给宿主进程，不会进入对话记录或日志。',
  ].join('\n')
}

/**
 * Escape text for a dialog that renders rich text.
 *
 * zenity is told `--no-markup`, but kdialog has no such switch: it renders Qt
 * rich text, so an unescaped command could paint part of itself invisible (or
 * repaint it as something else) while the shell still ran the whole string. The
 * escaping makes the dialog show the characters that will actually run.
 */
function escapeMarkup(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/**
 * @param deps - the password validator and the audit sink.
 */
export function createNativeDialog(deps) {
  const { audit, validatePassword } = deps

  /** Attempts allowed when sudo rejects the typed password. */
  const MAX_ATTEMPTS = 3

  /** Spawn one dialog and resolve its outcome. */
  function runOnce(text, timeoutMs, signal) {
    const chooser = resolveDialogBinary()
    if (chooser === undefined) return Promise.resolve({ kind: 'unavailable' })
    const env = {}
    for (const key of DISPLAY_ENV) {
      if (process.env[key] !== undefined) env[key] = process.env[key]
    }
    const args = []
    if (chooser.name === 'zenity') {
      args.push(
        // NOT `--password`: zenity 4.2.1's password dialog has no `--text`
        // option at all (see `zenity --help-password`), so it accepted the text
        // and discarded it — the dialog asked for a password for a command it
        // never showed. The entry dialog renders `--text` (verified against the
        // real binary, not just its argv), and `--hide-text` keeps the input
        // masked.
        '--entry',
        '--hide-text',
        // The command must appear exactly as it will run: `--no-markup` stops
        // Pango from treating `<span …>` as formatting and hiding a line that
        // still executes.
        '--no-markup',
        '--title=需要 sudo 授权',
        `--text=${text}`,
        '--ok-label=允许并执行',
        '--cancel-label=拒绝',
        '--width=760',
        `--timeout=${Math.max(1, Math.ceil(timeoutMs / 1000))}`,
      )
    } else {
      // kdialog has neither a timeout nor button labels; the caller's own timer
      // bounds the wait, and it still returns the password on stdout.
      args.push('--password', escapeMarkup(text), '--title', '需要 sudo 授权')
    }
    return new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        signal?.removeEventListener('abort', onAbort)
        resolve(value)
      }
      const onAbort = () => {
        child?.kill('SIGTERM')
        finish({ kind: 'cancelled' })
      }
      let child
      try {
        child = spawn(chooser.path, args, { stdio: ['ignore', 'pipe', 'ignore'], env })
      } catch {
        finish({ kind: 'unavailable' })
        return
      }
      if (signal?.aborted === true) {
        onAbort()
        return
      }
      signal?.addEventListener('abort', onAbort, { once: true })
      let out = ''
      child.stdout.setEncoding('utf8')
      child.stdout.on('data', (chunk) => {
        // A password is short; never buffer an unbounded stream.
        if (out.length < 4096) out += chunk
      })
      child.on('error', () => finish({ kind: 'unavailable' }))
      child.on('close', (code) => {
        if (code === 0) {
          const secret = out.replace(/\r?\n$/, '')
          finish(secret === '' ? { kind: 'empty' } : { kind: 'secret', secret })
          return
        }
        // zenity: 1 = dismissed/cancelled, 5 = the dialog's own timeout fired.
        if (code === 5) finish({ kind: 'timeout' })
        else finish({ kind: 'rejected' })
      })
    })
  }

  /**
   * Ask the host display for one approval.
   *
   * A wrong password re-opens the dialog instead of cancelling the request: the
   * Web panel keeps its input on screen, and a dialog that vanished on a typo
   * would make the model retry a command nobody actually refused.
   * @param request - the analysis to show, its check code, the total wait and the
   *   abort signal.
   * @returns `{kind:'approved',secret}` / `rejected` / `timeout` / `cancelled` /
   *   `unavailable`.
   */
  async function ask({ analysis, code, waitMs, signal }) {
    const deadlineAt = Date.now() + waitMs
    let note = ''
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      if (signal?.aborted === true) return { kind: 'cancelled' }
      const left = deadlineAt - Date.now()
      if (left < 1_000) return { kind: 'timeout' }
      const text = note === '' ? dialogText(analysis, code) : `${note}\n\n${dialogText(analysis, code)}`
      const outcome = await runOnce(text, left, signal)
      if (outcome.kind === 'empty') {
        note = '密码不能为空，请重试。'
        continue
      }
      if (outcome.kind !== 'secret') return outcome
      if (await validatePassword(outcome.secret)) return { kind: 'approved', secret: outcome.secret }
      audit({ event: 'invalid-password', dialog: 'native', attempt })
      note = '密码不正确，请重试。'
    }
    return { kind: 'rejected', reason: '密码连续 3 次不正确' }
  }

  return { ask }
}

/** Human-readable list of the missing signals, for a refusal reason. */
export function describeMissing(missing) {
  return missing.map((key) => MISSING_TEXT[key] ?? key).join('；')
}
