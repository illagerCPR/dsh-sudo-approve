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

const failed = results.filter((ok) => !ok).length
console.log(`\n${results.length - failed}/${results.length} checks matched`)
if (failed > 0) process.exitCode = 1
