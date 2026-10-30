// Native-dialog harness — drives the real modules with a FAKE zenity, so no
// window ever appears while testing. The fake is injected through an ESM loader
// redirect (see dsa-loader.mjs), because build 17 resolves the dialog on fixed
// root-owned paths instead of PATH: a fake on PATH must be ignored, and the
// production module must not grow a test switch just to stay testable.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { register } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

// A real password prompt is a property of this machine, not of the code: on a
// passwordless runner the checks that need a *wrong* password cannot fail, and
// the trusted-path check needs a real zenity to point at.
const passwordRequired = spawnSync('sudo', ['-n', 'true'], { stdio: 'ignore' }).status !== 0
const hasZenity = existsSync('/usr/bin/zenity')

// Every check applies the plugin to a fresh fake context, and each apply leaves
// a process-exit hook behind; ten of those is just how many checks there are.
process.setMaxListeners(0)

const home = mkdtempSync(join(tmpdir(), 'dsa-native-home-'))
process.env.DSH_HOME = home
process.env.XDG_RUNTIME_DIR = mkdtempSync(join(tmpdir(), 'dsa-native-run-'))

// --- a fake zenity that records its argv and answers from files --------------
// Two modes: a single `state.txt` for the old tests, and a scripted `steps.txt`
// (one answer per invocation) for the flows that need several dialogs in a row —
// reject, then type a reason into the follow-up dialog.
const fakeDir = mkdtempSync(join(tmpdir(), 'dsa-fake-bin-'))
const stateFile = join(fakeDir, 'state.txt')
const argsFile = join(fakeDir, 'args.txt')
const argsAll = join(fakeDir, 'args-all.txt')
const stepsFile = join(fakeDir, 'steps.txt')
const idxFile = join(fakeDir, 'idx.txt')
const pwFile = join(fakeDir, 'pw.txt')
writeFileSync(stateFile, 'ok')
writeFileSync(pwFile, 'hunter2\n')
writeFileSync(stepsFile, '')
writeFileSync(argsAll, '')
const fake = `#!/bin/sh
printf '%s\\n' "$@" > "${argsFile}"
printf -- '---\\n' >> "${argsAll}"
printf '%s\\n' "$@" >> "${argsAll}"
steps=$(cat "${stepsFile}" 2>/dev/null || echo '')
if [ -n "$steps" ]; then
  idx=$(cat "${idxFile}" 2>/dev/null || echo 0)
  idx=$((idx + 1))
  echo "$idx" > "${idxFile}"
  step=$(printf '%s\\n' "$steps" | sed -n "\${idx}p")
  case "$step" in
    ok) cat "${pwFile}" 2>/dev/null; exit 0 ;;
    cancel) exit 1 ;;
    timeout) exit 5 ;;
    multiline) printf 'line one\\nline two\\n'; exit 0 ;;
    text:*) printf '%s\\n' "\${step#text:}"; exit 0 ;;
    *) exit 1 ;;
  esac
fi
state=$(cat "${stateFile}" 2>/dev/null || echo ok)
case "$state" in
  ok) cat "${pwFile}" 2>/dev/null; exit 0 ;;
  cancel) exit 1 ;;
  timeout) exit 5 ;;
  hang) sleep 30; exit 0 ;;
esac
exit 1
`
writeFileSync(join(fakeDir, 'zenity'), fake)
chmodSync(join(fakeDir, 'zenity'), 0o755)
const realPath = process.env.PATH ?? ''
process.env.PATH = `${fakeDir}:${realPath}`
process.env.DSA_FAKE_ZENITY = join(fakeDir, 'zenity')
register(new URL('./loader.mjs', import.meta.url).href)
process.env.DISPLAY = ':0'
delete process.env.SSH_TTY
delete process.env.SSH_CONNECTION

const results = []
const disposers = []
const check = (name, ok, extra = '') => {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

/** Give the fake dialog one answer per invocation, in order. */
const scripted = (...steps) => {
  writeFileSync(stepsFile, `${steps.join('\n')}\n`)
  writeFileSync(idxFile, '0')
  writeFileSync(argsAll, '')
}

/** Drop back to the single-state fake the older checks use. */
const unscripted = (state = 'ok') => {
  writeFileSync(stepsFile, '')
  writeFileSync(idxFile, '0')
  writeFileSync(stateFile, state)
  writeFileSync(argsAll, '')
}

/** One entry per dialog the fake was asked to show, as their argv text. */
const invocations = () => readFileSync(argsAll, 'utf8').split(/^---$/m).slice(1)

function makeCtx(options = {}) {
  const { roots = [{ id: 'session-x' }], webServer } = options
  const handlers = new Map()
  const routes = new Map()
  const contexts = []
  const connection = { allowsRemoteAuthorities: false, fetch: { register: (route) => routes.set(route.path, route) } }
  const systemPrompt = { context: (spec) => contexts.push(spec), getContextOrder: () => 100 }
  const shell = { resolve: (request) => ({ command: request.command, workdir: '/tmp', timeoutMs: 1000 }) }
  const get = (name) => {
    if (name === 'shell') return shell
    if (name === 'agents') return { roots: () => roots }
    if (name === 'sandboxPolicy') return { resolve: () => ({ mode: 'danger-full-access' }) }
    if (name === 'connection') return connection
    if (name === 'systemPrompt') return systemPrompt
    if (name === 'webServer') return webServer
    return undefined
  }
  const ctx = {
    on: (name, fn) => handlers.set(name, fn),
    effect: (fn) => {
      const dispose = fn()
      if (typeof dispose === 'function') disposers.push(dispose)
    },
    get,
    inject: (_services, cb) => {
      cb({ get, systemPrompt, shell, connection })
      return { dispose: () => {} }
    },
  }
  return { ctx, handlers, routes, contexts }
}

const mod = await import(`${root}/index.js`)
const { DIALOG_WRAP_COLUMNS, NATIVE_MAX_ROWS, foldLine, nativeRowCount, sampleDialogFacts } =
  await import(`${root}/lib/native-dialog.js`)

const agent = { id: 'session-x', session: { cwd: '/tmp' } }
const callExec = (command, extra = {}) => ({ name: 'bash', callId: `c${Math.random().toString(16).slice(2)}`, agent, arguments: { command }, ...extra })
const denyReason = (verdict) => verdict?.reason ?? ''

// --- N1: facts and the dialog paragraph ------------------------------------
{
  const { ctx, contexts } = makeCtx()
  const facts = sampleDialogFacts(ctx)
  check('N1 a display plus a dialog binary is eligible', facts.eligible === true, JSON.stringify(facts.missing))

  mod.apply(ctx, { passwordDialog: 'auto' })
  const text = contexts[0].text({ agent })
  check('N2 auto picks the dialog when it can', text.includes('system dialog on the host') && !text.includes('in the GUI'), text.slice(0, 40))
  check('N3 the dialog variant reports its own smaller cap', text.includes('24 lines') && !text.includes('the panel shows'), '')
}

// --- N4: a non-loopback bind disqualifies the dialog ------------------------
{
  const { ctx } = makeCtx({ webServer: { host: '0.0.0.0' } })
  check('N4 a wildcard bind is not loopback', sampleDialogFacts(ctx).missing.includes('bind-address'))
  const loopback = makeCtx({ webServer: { host: '127.0.0.1' } })
  check('N5 a loopback bind is accepted', sampleDialogFacts(loopback.ctx).eligible === true)
}

// --- N6: the dialog line cap refuses before the page cap would -------------
{
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const preExecute = handlers.get('tools/pre-execute')
  const thirty = Array.from({ length: 30 }, (_, i) => `sudo echo ${i}`).join('\n')
  const verdict = await preExecute(callExec(thirty), () => 'dispatched')
  check('N6 30 lines fit the page but not the dialog', verdict?.kind === 'deny' && denyReason(verdict).includes('24 行'), denyReason(verdict).slice(0, 30))

  // The same command in browser mode is accepted (it fits 60 lines).
  const pageCtx = makeCtx()
  mod.apply(pageCtx.ctx, { passwordDialog: 'browser' })
  const pageVerdict = await pageCtx.handlers.get('tools/pre-execute')(callExec(thirty), () => 'dispatched')
  check(
    'N7 the page refuses it for the page, not for the dialog',
    pageVerdict?.kind === 'deny' && denyReason(pageVerdict).includes('没有已连接的浏览器页面'),
    denyReason(pageVerdict).slice(0, 18),
  )
}

// --- N8: the page cannot approve a native request --------------------------
{
  writeFileSync(stateFile, 'hang')
  const { ctx, handlers, routes } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const controller = new AbortController()
  const exec = callExec('sudo id -un', { signal: controller.signal })
  const pending = handlers.get('tools/pre-execute')(exec, () => 'dispatched')

  await new Promise((resolve) => setTimeout(resolve, 300))
  const pendingRoute = routes.get('/api/sudo-approve/pending')
  const listed = await (await pendingRoute.fetch(new Request('http://127.0.0.1/api/sudo-approve/pending?state=visible&interaction=1'))).json()
  const request = listed.value.requests[0]
  check('N8 the page sees the request read-only', request?.dialog === 'native' && request?.passwordRequired === false)
  // The code is what ties the window to this request: both surfaces must carry
  // the same six characters, or the operator cannot tell them apart.
  const codeOk = typeof request?.code === 'string' && /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/.test(request.code)
  check('N18 the pending request carries a check code', codeOk, String(request?.code))
  const dialogText = readFileSync(argsFile, 'utf8')
  check('N19 the dialog shows the same code as the page', dialogText.includes(`核对码 ${request?.code}`), '')
  const auditLine = readFileSync(join(home, 'logs', 'dsh-sudo-approve.log'), 'utf8')
    .split('\n')
    .find((line) => line.includes('"event":"request"') && line.includes(request?.id ?? ''))
  check('N20 the request audit line records the code', auditLine?.includes(`"code":"${request?.code}"`) === true, '')

  const respondRoute = routes.get('/api/sudo-approve/respond')
  const answer = await respondRoute.fetch(
    new Request('http://127.0.0.1/api/sudo-approve/respond', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: request.id, decision: 'approve', interaction: true, password: 'hunter2' }),
    }),
  )
  check('N9 a page approval is refused in native mode', answer.status === 409, `${answer.status} ${(await answer.json()).error?.code}`)
  check('N10 the dialog body shows the command', readFileSync(argsFile, 'utf8').includes('id -un'))

  controller.abort()
  const settled = await pending
  check('N11 aborting the call ends the gate', settled?.kind === 'cancel', JSON.stringify(settled))
  writeFileSync(stateFile, 'ok')
}

// --- N12: forced native without a dialog is refused, not degraded ----------
{
  process.env.SSH_TTY = '/dev/pts/9'
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'native' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check('N12 a forced dialog that cannot be shown is refused', verdict?.kind === 'deny' && denyReason(verdict).includes('SSH'), denyReason(verdict).slice(0, 26))

  const autoCtx = makeCtx()
  mod.apply(autoCtx.ctx, { passwordDialog: 'auto' })
  const fallback = await autoCtx.handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check('N13 auto falls back to the page instead', denyReason(fallback).includes('没有已连接的浏览器页面'), denyReason(fallback).slice(0, 20))
  delete process.env.SSH_TTY
}

// --- N14: a cancelled dialog is a refusal, and the argv looks right --------
{
  unscripted('cancel')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check('N14 cancelling the dialog denies the call', verdict?.kind === 'deny' && denyReason(verdict).includes('用户拒绝'), denyReason(verdict).slice(0, 22))
  // The approval dialog is the first one; a refusal is followed by the reason
  // dialog, so the last argv is no longer the one that matters here.
  const argv = (invocations()[0] ?? '').split('\n')
  check('N15 the dialog is asked with a timeout and labels', argv.some((line) => line.startsWith('--timeout=')) && argv.includes('--ok-label=允许并执行'))
  // zenity's --password has no text option and silently discards the command;
  // the entry dialog is the one that actually renders it.
  check(
    'N21 zenity is asked for the entry dialog, not --password',
    argv.includes('--entry') && argv.includes('--hide-text') && !argv.includes('--password'),
    argv.slice(0, 6).join(' '),
  )
  unscripted('ok')
}

// --- N16: a wrong password re-opens the dialog, then gives up -------------
if (passwordRequired) {
  writeFileSync(stateFile, 'ok')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo -k -V'), () => 'dispatched')
  const log = readFileSync(join(home, 'logs', 'dsh-sudo-approve.log'), 'utf8')
  const attempts = log.split('\n').filter((line) => line.includes('"event":"invalid-password"') && line.includes('"dialog":"native"')).length
  check('N16 three wrong attempts end in a refusal', verdict?.kind === 'deny' && denyReason(verdict).includes('3 次'), denyReason(verdict).slice(0, 24))
  check('N17 each attempt is audited', attempts === 3, String(attempts))
} else {
  console.log('SKIP  N16/N17 (passwordless sudo: a wrong password cannot be rejected)')
}

// --- P0: the dialog backend comes from trusted paths, never from PATH ------
if (hasZenity) {
  // Load the real resolver, bypassing the loader redirect the rest of this file
  // runs under.
  const real = await import(`${root}/lib/trusted.js?real`)
  const chosen = real.resolveDialogBinary()
  check('P0-1 a fake zenity earlier on PATH is not chosen', chosen?.path === '/usr/bin/zenity', String(chosen?.path))
  check(
    'P0-2 a same-user candidate is refused',
    real.resolveDialogBinary([{ name: 'zenity', path: join(fakeDir, 'zenity') }]) === undefined,
  )

  const linkDir = mkdtempSync(join(tmpdir(), 'dsa-link-'))
  symlinkSync('/usr/bin/zenity', join(linkDir, 'zenity'))
  check(
    'P0-3 a symlink is judged by its target',
    real.resolveDialogBinary([{ name: 'zenity', path: join(linkDir, 'zenity') }])?.path === '/usr/bin/zenity',
  )
} else {
  console.log('SKIP  P0 (no /usr/bin/zenity on this machine)')
}

// --- P1: the shown command cannot repaint itself ----------------------------
{
  unscripted('cancel')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const markup = "sudo echo '<b>hi</b>'"
  await handlers.get('tools/pre-execute')(callExec(markup), () => 'dispatched')
  // The refusal now opens a second (reason) dialog, so the approval one is the
  // first invocation, not the last argv this fake recorded.
  const argv = invocations()[0] ?? ''
  check('P1-1 zenity is told not to parse markup', argv.split('\n').includes('--no-markup'))
  check('P1-2 zenity still receives the command verbatim', argv.includes("sudo echo '<b>hi</b>'"))

  // kdialog has no such switch, so the text is escaped instead.
  process.env.DSA_FAKE_DIALOG_NAME = 'kdialog'
  writeFileSync(argsAll, '')
  const kdialog = makeCtx()
  mod.apply(kdialog.ctx, { passwordDialog: 'native' })
  await kdialog.handlers.get('tools/pre-execute')(callExec(markup), () => 'dispatched')
  const kdArgs = invocations()[0] ?? ''
  check('P1-3 a kdialog command is escaped instead', kdArgs.includes('&lt;b&gt;hi&lt;/b&gt;'), kdArgs.slice(0, 60))
  delete process.env.DSA_FAKE_DIALOG_NAME
  unscripted('ok')
}

// --- N35–N39: a long line is folded, so the window stops at its width ------
// The dialog neither wraps nor scrolls: a 300-character command made a 2074 px
// wide window on the real binary, and the buttons sat off screen. The body is
// folded on the Host instead, with a marker that keeps a fold from reading as a
// second command.
{
  const original = `sudo tee /etc/${'a'.repeat(200)}.conf <<< ok`
  const folded = foldLine(original)
  const rejoined = folded.map((row, index) => (index === 0 ? row : row.slice(2))).join('')
  check('N35 folding every character survives', rejoined === original, `${folded.length} rows`)
  check('N36 every folded row fits the budget', folded.every((row) => row.length <= DIALOG_WRAP_COLUMNS))
  check(
    'N37 only continuation rows carry the marker',
    folded.slice(1).every((row) => row.startsWith('↳ ')) && !folded[0].startsWith('↳ '),
  )
  // Wide characters count double, or a CJK line would still blow the width out.
  const cjk = foldLine('sudo ' + '汉'.repeat(100))
  check('N38 a wide-character line folds by display width', cjk.every((row) => row.length <= 44), String(cjk[0].length))

  unscripted('cancel')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  await handlers.get('tools/pre-execute')(callExec(`sudo cat /var/log/${'b'.repeat(180)}.log`), () => 'dispatched')
  const body = invocations()[0] ?? ''
  check(
    'N39 the dialog is asked for folded text',
    body.split('\n').every((row) => row.length <= DIALOG_WRAP_COLUMNS) && body.includes('↳ '),
    String(Math.max(...body.split('\n').map((row) => row.length))),
  )
  unscripted('ok')
}

// --- N40–N42: folding adds height, so a tall body is refused ---------------
{
  const tall = Array.from({ length: 7 }, () => `sudo echo ${'y'.repeat(390)}`).join('\n')
  // Seven 400-character lines pass the line caps and still draw 42 rows, which
  // is taller than the dialog: refuse rather than hide the last ones.
  check('N40 the folded row count is what the cap measures', nativeRowCount([{ text: tall.split('\n')[0] }]) === 6, '')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec(tall), () => 'dispatched')
  check(
    'N41 a body taller than the dialog is refused',
    verdict?.kind === 'deny' && denyReason(verdict).includes('显示行') && denyReason(verdict).includes(String(NATIVE_MAX_ROWS)),
    denyReason(verdict).slice(0, 40),
  )
  const denied = readFileSync(join(home, 'logs', 'dsh-sudo-approve.log'), 'utf8')
    .split('\n')
    .filter((line) => line.includes('"event":"denied"') && line.includes('"reason":"truncated"') && line.includes('"rows":42'))
    .at(-1)
  check('N42 the refusal records the folded row count', denied?.includes(`"rows":42`) === true && denied?.includes(`"rowCap":${NATIVE_MAX_ROWS}`) === true, denied?.slice(0, 80) ?? '')
}

// --- N22–N24: a rejection asks for a reason in a second dialog --------------
{
  scripted('cancel', 'text:太危险了')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check(
    'N22 a rejection carries the typed reason',
    verdict?.kind === 'deny' && denyReason(verdict).includes('拒绝理由：太危险了'),
    denyReason(verdict),
  )
  const calls = invocations()
  check('N23 the reason is asked in a second dialog', calls.length === 2, String(calls.length))
  // The reason dialog must be readable: a masked field there would invite a
  // password into a box whose contents end up in the transcript.
  check(
    'N24 the reason field is not masked and is labelled',
    calls[1]?.includes('--title=拒绝理由') === true &&
      calls[1]?.includes('--ok-label=提交理由') === true &&
      calls[1]?.includes('--hide-text') === false &&
      calls[0]?.includes('--hide-text') === true,
    '',
  )
}

// --- N25: skipping the reason leaves the refusal exactly as it was ----------
{
  scripted('cancel', 'cancel')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check(
    'N25 skipping the reason is a plain refusal',
    verdict?.kind === 'deny' && denyReason(verdict) === 'sudo 审批：用户拒绝执行该 sudo 命令。',
    denyReason(verdict),
  )
  check('N26 both dialogs were shown, none failed', invocations().length === 2, String(invocations().length))
}

// --- N27: three wrong passwords never becomes a reason question ------------
if (passwordRequired) {
  scripted('ok', 'ok', 'ok')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo -k -V'), () => 'dispatched')
  const calls = invocations()
  check(
    'N27 the automatic refusal keeps its own reason',
    verdict?.kind === 'deny' && denyReason(verdict).includes('3 次'),
    denyReason(verdict).slice(0, 26),
  )
  check('N28 no reason dialog follows the automatic refusal', calls.length === 3 && !calls[2].includes('拒绝理由'), String(calls.length))
} else {
  console.log('SKIP  N27/N28 (passwordless sudo)')
}

// --- N29: the timeout is still a timeout, not a refusal --------------------
{
  scripted('timeout')
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'auto' })
  const verdict = await handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check('N29 the dialog timing out is not a refusal', denyReason(verdict).includes('没有收到确认'), denyReason(verdict))
  check('N30 a timeout asks nothing further', invocations().length === 1, String(invocations().length))
}

// --- N31–N32: the reason is normalised like the page's ---------------------
{
  scripted('cancel', 'multiline')
  const first = makeCtx()
  mod.apply(first.ctx, { passwordDialog: 'auto' })
  const folded = await first.handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  check('N31 newlines in the reason are folded', denyReason(folded).includes('拒绝理由：line one line two'), denyReason(folded))

  scripted('cancel', `text:${'x'.repeat(250)}`)
  const second = makeCtx()
  mod.apply(second.ctx, { passwordDialog: 'auto' })
  const capped = await second.handlers.get('tools/pre-execute')(callExec('sudo id -un'), () => 'dispatched')
  const text = denyReason(capped)
  const reason = text.slice(text.indexOf('拒绝理由：') + '拒绝理由：'.length)
  check('N32 the reason is capped like the page caps it', reason.length === 201 && reason.endsWith('…'), String(reason.length))
}

// --- N33: kdialog keeps one dialog line per command line -------------------
{
  scripted('cancel', 'text:不放心')
  process.env.DSA_FAKE_DIALOG_NAME = 'kdialog'
  const { ctx, handlers } = makeCtx()
  mod.apply(ctx, { passwordDialog: 'native' })
  await handlers.get('tools/pre-execute')(callExec("sudo id -un\nsudo echo '<b>x</b>'"), () => 'dispatched')
  const calls = invocations()
  check(
    'N33 a kdialog body is escaped and joined with <br/>',
    calls[0]?.includes('&lt;b&gt;x&lt;/b&gt;') === true && calls[0]?.includes('<br/>') === true,
    calls[0]?.slice(0, 50),
  )
  check(
    'N34 kdialog asks the reason through an input box',
    calls[1]?.includes('--inputbox') === true && calls[1]?.includes('--password') === false,
    calls[1]?.slice(0, 40),
  )
  delete process.env.DSA_FAKE_DIALOG_NAME
}

for (const dispose of disposers) {
  try {
    dispose()
  } catch {
    // a torn-down install is not a test failure
  }
}

const failed = results.filter((result) => !result.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks matched`)
if (failed.length > 0) process.exitCode = 1
