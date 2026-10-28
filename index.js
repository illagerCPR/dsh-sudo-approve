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
 * This file is the assembly only. The refusals live in `lib/gate.js`, the shim
 * in `lib/shim.js`, the sudo hand-off in `lib/sudo-auth.js`; everything they
 * share is created here and passed in, including the approval scope, which must
 * be one instance rather than one per module.
 *
 * @module dsh-sudo-approve
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import { homedir } from 'node:os'
import { join } from 'node:path'

import { RUN_CODE_NAME } from './lib/agents.js'
import { createAudit } from './lib/audit.js'
import { createSettings } from './lib/config.js'
import { scanCoverage } from './lib/coverage.js'
import { createGate } from './lib/gate.js'
import { MESSAGES } from './lib/messages.js'
import { createNativeDialog, NATIVE_MAX_LINES, sampleDialogFacts } from './lib/native-dialog.js'
import { createPtc } from './lib/ptc.js'
import { installPrompt } from './lib/prompt.js'
import { installRoutes } from './lib/routes.js'
import { createShim } from './lib/shim.js'
import { createSudoAuth } from './lib/sudo-auth.js'
import { resolveTrusted } from './lib/trusted.js'
import { errorText, isPlainObject } from './lib/util.js'

/** Plugin identity used in route paths, log lines and dir prefixes. */
const NAME = 'dsh-sudo-approve'
/** Bumped whenever a change has to be confirmed as live in the running Host. */
const BUILD = 22
/** Fallback PATH when the Host process has none. */
const FALLBACK_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

/**
 * Candidates for the real sudo.
 *
 * Resolution is confined to root-owned locations and re-validated after
 * `realpath` (see `lib/trusted`), because the password is handed to whatever
 * binary this ends up naming: a writable directory on `PATH` must never be able
 * to answer that question.
 */
const SUDO_CANDIDATES = Object.freeze(['/usr/bin/sudo', '/bin/sudo'])
/** The same treatment for sudoedit, which the shim also shadows. */
const SUDOEDIT_CANDIDATES = Object.freeze(['/usr/bin/sudoedit', '/bin/sudoedit'])

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
  const audit = createAudit(auditLog)

  const settings = createSettings({ installConfig, storePath, build: BUILD, auditLog, sudoOf: () => realSudo?.path })
  const config = () => settings.get()

  // The trusted binary is resolved from the effective config, so a `sudoPath`
  // saved in the store is honoured the same way an install-time one is.
  const realSudo = resolveTrusted(config().sudoPath, SUDO_CANDIDATES)
  const realSudoedit = resolveTrusted('', SUDOEDIT_CANDIDATES)

  if (realSudo === undefined) {
    audit({ event: 'inactive', reason: 'sudo-not-trusted' })
    return
  }

  // Sampled once per boot, like the Harness directory picker: a display session
  // that shows dialogs now will still show them a minute later, and a surface
  // that cannot be shown must not be re-decided mid-command.
  const dialogFacts = sampleDialogFacts(ctx)
  /**
   * Which surface answers this call, and how much it can show.
   *
   * `unavailable` is the forced-native case: a dialog was asked for that this
   * deployment cannot show. Waiting on a surface nobody can see is refused
   * rather than silently degraded back to the page.
   */
  const surfaceOf = () => {
    const configured = config().passwordDialog
    if (configured !== 'browser' && dialogFacts.eligible) {
      return { mode: 'native', missing: [], maxLines: NATIVE_MAX_LINES }
    }
    if (configured === 'native') return { mode: 'unavailable', missing: dialogFacts.missing, maxLines: NATIVE_MAX_LINES }
    return { mode: 'browser', missing: dialogFacts.missing, maxLines: 60 }
  }

  /**
   * The coverage answer, read on demand.
   *
   * Reading it at apply time is not enough: the tool registry service comes up
   * after this plugin is applied, and its contents fill in after that (the first
   * two boots of this build logged `available:false`, then an empty list). A
   * read is therefore only treated as an answer once the tools this gate claims
   * to cover are visible in it; anything earlier is a partial view worth one
   * audit line, not a verdict.
   *
   * Both stages are logged at most once, so the record shows how the view filled
   * in without burying it in retries: "unknown" must never be filed as "checked".
   */
  const stages = { none: 0, partial: 1, final: 2 }
  let coverageStage = 'none'
  /**
   * The views worth reading: the global registry plus every live session's own.
   *
   * A tool can be mounted inside an agent composition rather than globally, and
   * `bash` is exactly that on this Host: the global view alone never shows it,
   * which is why the first attempts could not settle. The runtime reads
   * `schemas(agent)` for the same reason when it lists an agent's tools.
   */
  const coverageScopes = () => {
    const agents = ctx.get('agents')
    const list = typeof agents?.list === 'function' ? agents.list() : []
    return [undefined, ...list.filter((agent) => agent !== undefined)]
  }
  const coverageOf = () => {
    const report = scanCoverage(ctx.get('tools'), config().toolNames, coverageScopes())
    const stage = report.available ? 'final' : report.total > 0 ? 'partial' : 'none'
    if (stages[stage] > stages[coverageStage]) {
      coverageStage = stage
      audit({
        event: 'coverage',
        final: stage === 'final',
        views: report.views,
        tools: report.total,
        covered: report.covered,
        uncovered: report.uncovered,
        // The PTC transport is a command surface the name/field heuristic cannot
        // classify; naming it here keeps "covered: bash" from reading like "the
        // only way to run a command".
        ...(report.programs.length > 0 ? { programs: report.programs } : {}),
      })
    }
    return report
  }

  audit({
    event: 'loaded',
    build: BUILD,
    remember: config().remember,
    credential: config().credential,
    timeoutMs: config().timeoutMs,
    sudo: realSudo.path,
    passwordDialog: config().passwordDialog,
    dialog: surfaceOf().mode,
    // Which binary the trusted resolver picked, so the boot line says exactly
    // what will collect the password rather than just "native".
    dialogBinary: dialogFacts.chooser?.path,
  })

  // The registry service comes up before its tools do, so the first read is
  // usually too early. Ask again soon after, and keep asking on the lifecycle
  // loop, until a read can see the tools this gate covers.
  ctx.effect(() => {
    const scope = ctx.inject(['tools'], () => {
      coverageOf()
    })
    const timers = [2_000, 8_000].map((delay) =>
      setTimeout(() => {
        if (coverageStage !== 'final') coverageOf()
      }, delay),
    )
    return () => {
      scope?.dispose?.()
      for (const timer of timers) clearTimeout(timer)
    }
  }, `${NAME}: coverage`)

  /** sessionId → { secret, usedAt } in `remember` mode. */
  const remembered = new Map()
  /**
   * The approval store. One instance, created here and handed to both the shim
   * and the sudo hand-off: a second instance would silently see nothing, because
   * an AsyncLocalStorage only answers for the object that opened the scope.
   */
  const approvalScope = new AsyncLocalStorage()

  /** A config change that drops `remember:session` invalidates every memo. */
  settings.onApply = (next) => {
    if (next.remember !== 'session') remembered.clear()
  }

  const shim = createShim({
    name: NAME,
    scope: approvalScope,
    basePath: process.env.PATH ?? FALLBACK_PATH,
    realSudo,
    realSudoedit,
    audit,
  })

  shim.installScoped(ctx)
  shim.sweepStaleRuns()

  const sudoAuth = createSudoAuth({
    realSudo,
    basePath: process.env.PATH ?? FALLBACK_PATH,
    scope: approvalScope,
    config,
    audit,
    shim,
  })

  const ptc = createPtc({ ctx, config })

  const nativeDialog = createNativeDialog({ audit, validatePassword: sudoAuth.validatePassword })

  const gate = createGate({ ctx, config, audit, remembered, ptc, surfaceOf, nativeDialog })

  installPrompt({ ctx, name: NAME, config, ptc, surfaceOf })
  installRoutes({
    ctx,
    name: NAME,
    config,
    audit,
    settings,
    gate,
    remembered,
    validatePassword: sudoAuth.validatePassword,
    surfaceOf,
    coverageOf,
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    let verdict
    try {
      verdict = await gate.check(exec)
    } catch (error) {
      audit({ event: 'gate-error', message: errorText(error) })
      return { kind: 'deny', reason: MESSAGES.internal(errorText(error)) }
    }
    if (verdict !== undefined) return verdict
    return next()
  })

  ctx.on('tools/execute', async (exec, next) => {
    // Time a PTC program from the moment its dispatch starts: its budget is
    // fixed here, and a nested sudo request later needs what is left of it.
    if (exec.name === RUN_CODE_NAME && exec.parent === undefined) {
      ptc.startProgram(exec.token)
      try {
        return await next()
      } finally {
        ptc.endProgram(exec.token)
      }
    }
    const entry = gate.takeArmed(exec)
    if (entry === undefined) return next()
    return sudoAuth.dispatchWithSecret(exec, entry.secret, next)
  })

  // A disposed session drops its remembered password.
  ctx.on('session/disposed', (session) => {
    remembered.delete(session?.id)
  })

  ctx.effect(() => {
    const onExit = () => shim.hardCleanup()
    process.on('exit', onExit)
    const timer = setInterval(() => {
      if (coverageStage !== 'final') coverageOf()
      const now = Date.now()
      gate.pruneArmed(now)
      for (const [sessionId, memo] of remembered) {
        if (now - memo.usedAt > config().memoryTtlMs) remembered.delete(sessionId)
      }
    }, 30_000)
    return () => {
      process.off('exit', onExit)
      clearInterval(timer)
      shim.hardCleanup()
      // Unload either way: queued models must not wait for a panel that will
      // never come, so every waiter is settled before the state is dropped.
      gate.settleAll()
      gate.disarmAll()
      remembered.clear()
      ptc.clear()
    }
  }, `${NAME}: lifecycle`)
}
