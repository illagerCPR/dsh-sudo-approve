// First-render smoke test for the client half: boots the real factory with a
// fake React and a fake Harness ctx, then renders the settings section exactly
// once — the state that used to throw and blank the whole page.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('..', import.meta.url))

const src = readFileSync(`${root}/client.js`, 'utf8')

let factory
globalThis.window = {
  __ModuleLoader__: {
    load: (mod) => {
      factory = mod.factory
    },
  },
  setInterval: () => 0,
  clearInterval: () => {},
}
globalThis.document = {
  visibilityState: 'visible',
  addEventListener: () => {},
  removeEventListener: () => {},
  createElement: () => ({ textContent: '', dataset: {}, remove() {}, setAttribute() {} }),
  head: { append: () => {}, appendChild: () => {} },
  body: { appendChild: () => {} },
}
globalThis.fetch = () => Promise.reject(new Error('network disabled in this test'))

const React = {
  createElement: (type, props, ...children) => ({ type, props, children }),
  useState: (initial) => [typeof initial === 'function' ? initial() : initial, () => {}],
  useCallback: (fn) => fn,
  useEffect: () => {},
  useRef: (value) => ({ current: value }),
}

// eslint-disable-next-line no-eval
eval(src)
if (typeof factory !== 'function') {
  console.log('FAIL  the module never registered itself')
  process.exit(1)
}

const requireFake = (name) => {
  if (name === 'react') return React
  throw new Error(`unexpected require(${name})`)
}

const registrations = []
const ctx = {
  effect: (fn) => {
    const dispose = fn()
    return typeof dispose === 'function' ? dispose : () => {}
  },
  get: () => undefined,
  inject: (_services, cb) => {
    cb()
    return { dispose: () => {} }
  },
  locale: { register: () => {}, bind: () => (key) => key },
  uiSession: { registerPendingInteraction: () => () => 0 },
  slots: {
    inject: (_name, cb) => cb(),
    register: (spec, component) => {
      registrations.push({ spec, component })
      return () => {}
    },
  },
}

const results = []
const check = (name, ok, extra = '') => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra === '' ? '' : `  [${extra}]`}`)
}

let mod
try {
  mod = factory(requireFake)
  check('C1 the client module evaluates', typeof mod?.apply === 'function')
} catch (error) {
  check('C1 the client module evaluates', false, error.message)
  process.exit(1)
}

try {
  mod.apply(ctx)
  check('C2 apply registers its surfaces', registrations.length >= 2, String(registrations.length))
} catch (error) {
  check('C2 apply registers its surfaces', false, error.message)
  console.log(error.stack)
  process.exit(1)
}

const settings = registrations.find((entry) => entry.spec.name === 'settings.section')
check('C3 the settings section is registered', settings !== undefined)

let tree
try {
  tree = settings.component()
  check('C4 the settings section renders before the config request lands', tree !== undefined)
  const flat = JSON.stringify(tree)
  check('C5 the password-surface row is in the tree', flat.includes('"key":"dialog"'), '')
} catch (error) {
  check('C4 the settings section renders before the config request lands', false, error.message)
  process.exit(1)
}

const composer = registrations.find((entry) => entry.spec.name === 'conversation.composer')
try {
  const pending = { snapshot: { id: 'x', sessionId: 's', items: [{ text: 'sudo id', sudo: true, privileged: true }], dialog: 'native', passwordRequired: false, code: 'K7QF2M', expiresAt: Date.now() + 60_000 } }
  const panel = composer.component({ matched: pending })
  const text = JSON.stringify(panel)
  check('C6 the panel renders in native mode', text.includes('nativeWaiting') || text.includes('dsa-native'), '')
  check('C7 no password field in native mode', !text.includes('dsa-password'))
  check('C10 the panel shows the check code', text.includes('dsa-code-chip') && text.includes('K7QF2M'))
  check('C11 the native hint points at the dialog', text.includes('checkCodeHintNative'))
  const page = composer.component({ matched: { ...pending, snapshot: { ...pending.snapshot, dialog: 'browser', passwordRequired: true } } })
  const pageText = JSON.stringify(page)
  check('C12 the page mode says no dialog will appear', pageText.includes('checkCodeHintBrowser') && pageText.includes('K7QF2M'))
} catch (error) {
  check('C6 the panel renders in native mode', false, error.message)
}

// The coverage row renders on the very first render too (no snapshot yet), and
// must say why it is empty rather than pretending everything is covered.
const flatSettings = JSON.stringify(tree)
check('C8 the coverage row is in the tree', flatSettings.includes('"key":"coverage"'))
check('C9 it admits the unknown instead of claiming coverage', flatSettings.includes('coverageUnknown'))
// The PTC program-channel row only renders once the Host reports a transport;
// this fake snapshot cannot reach that state, so check what the source must
// contain: a conditional row and the value that names the channel.
check('C13 the settings page has a PTC channel row', src.includes("readonlyRow('programs'") && src.includes('coverageWithPrograms'))

// --- an inactive Host explains itself instead of drawing the form ----------
// The component is re-rendered for real here: a stateful fake React, a mocked
// `/config` that answers `active: false`, and a mount/effect cycle that mirrors
// what the browser does, because the defect lived in the second render (the
// first one has no snapshot yet and used to look identical either way).
const jsonResponse = (payload, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => payload,
})

{
  const inactivePayload = {
    build: 24,
    active: false,
    reason: 'sudo-not-trusted',
    sudo: { path: '/usr/bin/sudo', check: 'untrusted-directory', mode: '777', candidates: ['/usr/bin/sudo'] },
    store: '/tmp/dsh-sudo-approve.json',
    auditLog: '/tmp/logs/dsh-sudo-approve.log',
  }

  const states = []
  const effects = []
  const cleanups = []
  let hookAt = 0
  let mounted = false
  let component = undefined
  let tree = undefined
  const renderPanel = () => {
    hookAt = 0
    effects.length = 0
    const next = component()
    if (!mounted) {
      mounted = true
      for (const fn of effects) {
        const cleanup = fn()
        if (typeof cleanup === 'function') cleanups.push(cleanup)
      }
    }
    return next
  }
  const StatefulReact = {
    createElement: (type, props, ...children) => ({ type, props, children }),
    useState: (initial) => {
      const at = hookAt++
      if (!(at in states)) states[at] = typeof initial === 'function' ? initial() : initial
      const setValue = (next) => {
        const value = typeof next === 'function' ? next(states[at]) : next
        if (Object.is(value, states[at])) return
        states[at] = value
        Promise.resolve().then(() => {
          tree = renderPanel()
        })
      }
      return [states[at], setValue]
    },
    useCallback: (fn) => fn,
    useEffect: (fn) => {
      effects.push(fn)
    },
    useRef: (value) => ({ current: value }),
  }

  const seenUrls = []
  globalThis.fetch = async (url) => {
    const target = String(url)
    seenUrls.push(target)
    if (target.includes('/pending')) return jsonResponse({ ok: true, value: { requests: [], waiting: 0 } })
    return jsonResponse({ ok: true, value: inactivePayload })
  }

  const inactiveRegistrations = []
  const makeInactiveCtx = () => ({
    effect: (fn) => {
      const dispose = fn()
      return typeof dispose === 'function' ? dispose : () => {}
    },
    get: () => undefined,
    inject: (_services, cb) => {
      cb()
      return { dispose: () => {} }
    },
    locale: { register: () => {}, bind: () => (key, params) => (params === undefined ? key : `${key}${JSON.stringify(params)}`) },
    uiSession: { registerPendingInteraction: () => () => 0 },
    slots: {
      inject: (_name, cb) => cb(),
      register: (spec, record) => {
        inactiveRegistrations.push({ spec, component: record })
        return () => {}
      },
    },
  })

  let inactiveModule
  try {
    inactiveModule = factory((name) => {
      if (name === 'react') return StatefulReact
      throw new Error(`unexpected require(${name})`)
    })
    inactiveModule.apply(makeInactiveCtx())
    check('C14 the client loads against an inactive Host', typeof inactiveModule?.apply === 'function')
  } catch (error) {
    check('C14 the client loads against an inactive Host', false, error.message)
  }

  const spec = inactiveRegistrations.find((entry) => entry.spec.name === 'settings.section')
  component = spec?.component
  try {
    // Mount first: the config request is started by this render's effect, so
    // rendering after the wait would only ever see the pre-request state.
    tree = renderPanel()
    await new Promise((resolve) => setImmediate(resolve))
    await new Promise((resolve) => setImmediate(resolve))
    tree = renderPanel()
  } catch (error) {
    check('C15 the inactive settings section renders', false, error.message)
  }
  const flat = JSON.stringify(tree)
  check('C15 the inactive settings section renders', tree !== undefined)
  check('C16 it says the plugin is not running', flat.includes('inactiveTitle'))
  check('C17 it never claims interception is on', !flat.includes('"key":"enabled"') && !flat.includes('"key":"dialog"'))
  check('C18 it names the failed check and the path', flat.includes('inactiveReasonDir') && flat.includes('/usr/bin/sudo'))
  check('C19 it points at the audit log', flat.includes('inactiveAudit'))
  for (const cleanup of cleanups.splice(0)) {
    try {
      cleanup()
    } catch {
      // a torn-down page is not a test failure
    }
  }
}

// --- the pending poll stops once the Host says it has no such route --------
{
  let intervalFn = undefined
  let cleared = 0
  const previousSet = globalThis.window.setInterval
  const previousClear = globalThis.window.clearInterval
  globalThis.window.setInterval = (fn) => {
    intervalFn = fn
    return 42
  }
  globalThis.window.clearInterval = () => {
    cleared += 1
  }
  let fetches = 0
  globalThis.fetch = async () => {
    fetches += 1
    return { ok: false, status: 404, json: async () => ({ ok: false }) }
  }

  const pollRegistrations = []
  const pollCtx = {
    effect: (fn) => {
      const dispose = fn()
      return typeof dispose === 'function' ? dispose : () => {}
    },
    get: () => undefined,
    inject: (_services, cb) => {
      cb()
      return { dispose: () => {} }
    },
    locale: { register: () => {}, bind: () => (key) => key },
    uiSession: { registerPendingInteraction: () => () => 0 },
    slots: {
      inject: (_name, cb) => cb(),
      register: (spec, record) => {
        pollRegistrations.push({ spec, component: record })
        return () => {}
      },
    },
  }
  const pollModule = factory(requireFake)
  pollModule.apply(pollCtx)
  await new Promise((resolve) => setImmediate(resolve))
  await new Promise((resolve) => setImmediate(resolve))
  check('C20 a 404 from the pending route ends the poll', cleared === 1 && intervalFn !== undefined, `cleared=${cleared}`)
  const after = fetches
  if (typeof intervalFn === 'function') intervalFn()
  await new Promise((resolve) => setImmediate(resolve))
  check('C21 no further request is sent after that', fetches === after, `${after} -> ${fetches}`)
  globalThis.window.setInterval = previousSet
  globalThis.window.clearInterval = previousClear
}

const failed = results.filter((ok) => !ok).length
console.log(`\n${results.length - failed}/${results.length} checks matched`)
if (failed > 0) process.exitCode = 1
