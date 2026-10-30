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
 *
 * kdialog does render the text (verified the same way), but it renders Qt rich
 * text, has no `--no-markup`, and folds literal newlines into spaces: every
 * command line would run together into one paragraph. Its text is therefore
 * escaped and re-joined with `<br/>`, so one line of the command stays one line
 * of the dialog.
 *
 * A rejection can carry a reason in both backends: after the approval window is
 * dismissed, a second dialog asks for one sentence and is skippable in a click.
 * It mirrors the page, where "拒绝" also opens an optional reason field.
 * @module dsh-sudo-approve/lib/native-dialog
 */

import { spawn } from 'node:child_process'

import { resolveDialogBinary } from './trusted.js'
import { normalizeReason } from './util.js'

/**
 * Line cap for the dialog.
 *
 * A system dialog has no scrollbar, so text taller than the screen would hide
 * part of the command while still asking for approval — the one thing an
 * approval surface must never do. Native mode therefore refuses earlier than the
 * Web panel (60) rather than showing a clipped command.
 *
 * The unit is a *command* line, the same one the page lists: a long line is
 * folded for display (see {@link DIALOG_WRAP_COLUMNS}) but stays one command.
 */
export const NATIVE_MAX_LINES = 24

/**
 * Column budget for one displayed row.
 *
 * Neither backend wraps: zenity sizes the whole window to its longest line, so
 * one 300-character command produced a 2074 px wide window and a 382-character
 * one would have run past a 1920 px screen — with the buttons off screen. The
 * body is therefore folded here, by display width, before it reaches the dialog.
 *
 * 80 columns keeps the worst case inside the `--width=760` the dialog asks for
 * (measured on zenity 4.2.1: 80 wide `M`s ≈ 949 px, ordinary command text far
 * less), so the window stops growing and the height grows only for text that
 * really is long.
 */
export const DIALOG_WRAP_COLUMNS = 80

/**
 * Row cap for the dialog body, counted the way the dialog draws it.
 *
 * Folding turns rows into height: a 24-line command of 400-character lines would
 * become 120 rows, taller than the screen and unapprovable. The cap is measured
 * after folding so the body always fits on screen in one piece.
 */
export const NATIVE_MAX_ROWS = 30

/**
 * Prefix of a row that continues the command line above it.
 *
 * A fold is a display detail, but the dialog is the only place the operator sees
 * what will run: without a marker a wrapped line would read as a second command.
 * The marker is announced in the dialog text and cannot appear at the start of a
 * shown command line, because the panel only lists trimmed lines.
 */
const CONTINUATION = '↳ '

/** Display width of the continuation marker. */
const CONTINUATION_COLUMNS = 2

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
 * Display columns one character occupies in the dialog.
 *
 * Counting characters is not enough: a dialog row of 80 CJK characters is more
 * than twice as wide as 80 Latin ones, and the whole point of the budget is that
 * the window stops growing. Ranges are taken conservatively — folding a little
 * earlier costs nothing, folding late reopens the bug.
 * @param character - one code point of the command.
 */
function columnsOf(character) {
  const code = character.codePointAt(0) ?? 0
  if (code < 0x1100) return 1
  const wide =
    code <= 0x115f || // Hangul Jamo
    (code >= 0x2e80 && code <= 0xa4cf) || // CJK radicals through Yi
    (code >= 0xac00 && code <= 0xd7a3) || // Hangul syllables
    (code >= 0xf900 && code <= 0xfaff) || // CJK compatibility ideographs
    (code >= 0xfe30 && code <= 0xfe6f) || // CJK compatibility forms
    (code >= 0xff00 && code <= 0xff60) || // fullwidth forms
    (code >= 0xffe0 && code <= 0xffe6) ||
    (code >= 0x1f300 && code <= 0x1f9ff) || // emoji
    (code >= 0x20000 && code <= 0x3fffd)
  return wide ? 2 : 1
}

/**
 * Fold one command line into the rows the dialog can draw.
 *
 * Only line structure changes: every character of the line survives, in order,
 * and continuation rows carry the marker so the reader can tell a fold from a
 * second command. That is what keeps the invariant intact — the operator still
 * sees the whole string that will run, just laid out to fit the window.
 * @param text - one trimmed command line.
 * @param columns - display columns per row.
 * @returns the rows, at least one.
 */
export function foldLine(text, columns = DIALOG_WRAP_COLUMNS) {
  const budget = Math.max(CONTINUATION_COLUMNS + 8, columns)
  const rows = []
  let row = ''
  let used = 0
  for (const character of text) {
    const width = columnsOf(character)
    if (used > 0 && used + width > budget) {
      rows.push(row)
      row = CONTINUATION
      used = CONTINUATION_COLUMNS
    }
    row += character
    used += width
  }
  rows.push(row)
  return rows
}

/**
 * How many rows the dialog body takes once the command is folded.
 *
 * The caller uses this as the cap that keeps the window on screen: rows are
 * height, and a dialog taller than the display hides the buttons it is asking
 * the operator to press.
 * @param items - the analyzed command lines.
 * @param columns - display columns per row.
 */
export function nativeRowCount(items, columns = DIALOG_WRAP_COLUMNS) {
  let rows = 0
  for (const item of items) rows += foldLine(item.text, columns).length
  return rows
}

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
  const rows = []
  let folded = false
  for (const item of analysis.items) {
    const itemRows = foldLine(item.text)
    if (itemRows.length > 1) folded = true
    rows.push(...itemRows)
  }
  return [
    `即将以 root 执行以下 ${analysis.items.length} 行命令：`,
    ...(folded ? ['以 ↳ 开头的行是上一行的折行显示，命令内容没有改变。'] : []),
    '',
    rows.join('\n'),
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
 * Escape a multi-line text for kdialog and keep its line structure.
 *
 * kdialog renders rich text and folds a literal newline into a space, so a
 * command of three lines arrived as one run-on paragraph — the operator could no
 * longer see where one command ended. Escaping first and joining with `<br/>`
 * afterwards restores one dialog line per command line without letting the
 * command paint itself.
 */
function markupLines(text) {
  return text.split('\n').map(escapeMarkup).join('<br/>')
}

/**
 * @param deps - the password validator and the audit sink.
 */
export function createNativeDialog(deps) {
  const { audit, validatePassword } = deps

  /** Attempts allowed when sudo rejects the typed password. */
  const MAX_ATTEMPTS = 3

  /** Longest a rejection reason may take; the refusal itself is already decided. */
  const REASON_BUDGET_MS = 60_000

  /** Below this there is no time left to ask, and asking could turn a refusal into a timeout. */
  const REASON_MIN_MS = 3_000

  /**
   * Spawn one dialog and report how it exited.
   *
   * Every dialog is spawned the same way: display-only environment, stdout
   * collected under a small cap, and the abort signal closing the window, so a
   * request nobody waits for cannot leave a modal on the operator's screen.
   */
  function runBinary(chooser, args, signal) {
    const env = {}
    for (const key of DISPLAY_ENV) {
      if (process.env[key] !== undefined) env[key] = process.env[key]
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
        // A password or a reason is short; never buffer an unbounded stream.
        if (out.length < 4096) out += chunk
      })
      child.on('error', () => finish({ kind: 'unavailable' }))
      child.on('close', (code) => finish({ kind: 'exit', code, out }))
    })
  }

  /** Arguments for one approval dialog of the chosen backend. */
  function approvalArgs(chooser, text, timeoutMs) {
    if (chooser.name === 'zenity') {
      return [
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
      ]
    }
    // kdialog has neither a timeout nor button labels for this dialog; the
    // caller's own timer bounds the wait, and it still returns the password on
    // stdout. Its text is rich text that folds newlines into spaces, so the
    // lines are joined explicitly (see `markupLines`).
    return ['--password', markupLines(text), '--title', '需要 sudo 授权']
  }

  /** Ask the approval dialog once. */
  async function runOnce(text, timeoutMs, signal) {
    const chooser = resolveDialogBinary()
    if (chooser === undefined) return { kind: 'unavailable' }
    const result = await runBinary(chooser, approvalArgs(chooser, text, timeoutMs), signal)
    if (result.kind !== 'exit') return result
    if (result.code === 0) {
      const secret = result.out.replace(/\r?\n$/, '')
      return secret === '' ? { kind: 'empty' } : { kind: 'secret', secret }
    }
    // zenity: 1 = dismissed/cancelled, 5 = the dialog's own timeout fired.
    if (result.code === 5) return { kind: 'timeout' }
    return { kind: 'rejected' }
  }

  /**
   * Ask the operator for a rejection reason.
   *
   * The page turns "拒绝" into an optional reason field; the approval dialog has
   * no room for that (one window, two buttons, one meaning each), so the
   * question is asked right after the refusal. Skipping — the second button,
   * Esc, closing the window, or running out of time — leaves the rejection
   * exactly as it was, without a reason.
   * @param deadlineAt - when the whole request stops waiting.
   * @returns the one-line reason, or undefined.
   */
  async function askRejectReason(deadlineAt, signal) {
    if (signal?.aborted === true) return undefined
    // Never trade a decided refusal for a timeout: too little budget left means
    // no question at all.
    const left = deadlineAt - Date.now()
    if (left < REASON_MIN_MS) return undefined
    const chooser = resolveDialogBinary()
    if (chooser === undefined) return undefined
    const seconds = Math.max(1, Math.ceil(Math.min(REASON_BUDGET_MS, left - 500) / 1000))
    const text = [
      '你刚刚拒绝了这条 sudo 命令。',
      '',
      '可以留一句话说明原因，它会转告给智能体（最长 200 字）；',
      '直接点「跳过」就不带理由。',
    ].join('\n')
    const args =
      chooser.name === 'zenity'
        ? [
            // Not `--hide-text`: this field is read, not secret.
            '--entry',
            '--no-markup',
            '--title=拒绝理由',
            `--text=${text}`,
            '--ok-label=提交理由',
            '--cancel-label=跳过',
            '--width=760',
            `--timeout=${seconds}`,
          ]
        : ['--inputbox', markupLines(text), '', '--title', '拒绝理由']
    const result = await runBinary(chooser, args, signal)
    if (result.kind !== 'exit' || result.code !== 0) return undefined
    return normalizeReason(result.out)
  }

  /**
   * Ask the host display for one approval.
   *
   * A wrong password re-opens the dialog instead of cancelling the request: the
   * Web panel keeps its input on screen, and a dialog that vanished on a typo
   * would make the model retry a command nobody actually refused.
   * @param request - the analysis to show, its check code, the total wait and the
   *   abort signal.
   * @returns `{kind:'approved',secret}` / `{kind:'rejected',reason?}` /
   *   `timeout` / `cancelled` / `unavailable`. The reason only exists when the
   *   operator typed one into the follow-up dialog; a rejection without one is
   *   the same rejection that existed before that dialog.
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
      if (outcome.kind === 'rejected') {
        // A refusal the operator just made: ask for a reason the same way the
        // page does, without ever delaying or changing the refusal itself.
        return { kind: 'rejected', reason: await askRejectReason(deadlineAt, signal) }
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
