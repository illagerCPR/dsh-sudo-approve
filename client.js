/**
 * dsh-sudo-approve — Web client half.
 *
 * Polls the Host for a pending sudo confirmation and, while one exists, takes
 * over the current Session's composer with a password panel. Approving posts
 * the password once to the Host; it never becomes a chat message, so it never
 * reaches the model context or the session log.
 *
 * Pure view code: no Harness Client package is imported, styling uses only
 * `--dsw-alias-*` tokens, and every resource is owned by `apply`.
 */

window.__ModuleLoader__.load({
  id: 'dsh-sudo-approve',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'dsh-sudo-approve'
    const PENDING_ENDPOINT = 'api/sudo-approve/pending'
    const RESPOND_ENDPOINT = 'api/sudo-approve/respond'
    const POLL_MS = 1500

    const zh = {
      title: '需要 sudo 授权',
      subtitle: '确认后会用该密码执行下面的命令；密码只提交给 Host，不会进入对话上下文或会话记录。',
      password: '输入登录密码',
      approve: '允许并执行',
      reject: '拒绝',
      working: '处理中…',
      remembered: '已记住本次会话的密码，可直接允许',
      invalidPassword: '密码不正确，请重试。',
      passwordRequired: '请输入密码。',
      stale: '该请求已失效。',
      failed: '提交失败，请重试。',
      remainingHint: '剩余时间',
    }

    const en = {
      title: 'sudo approval required',
      subtitle: 'Approving runs the commands below with this password. It is sent to the Host only and never enters the conversation or the session log.',
      password: 'Enter your login password',
      approve: 'Allow and run',
      reject: 'Reject',
      working: 'Working…',
      remembered: 'This session already remembers the password',
      invalidPassword: 'Wrong password. Try again.',
      passwordRequired: 'Enter the password.',
      stale: 'This request is no longer pending.',
      failed: 'Could not submit. Try again.',
      remainingHint: 'time left',
    }

    const CSS = `
.dsa-panel{box-sizing:border-box;display:flex;flex-direction:column;gap:8px;padding:12px 14px;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.55}
.dsa-head{display:flex;align-items:center;gap:8px}
.dsa-lock{font-size:14px;line-height:1}
.dsa-title{flex:1 1 auto;font-weight:600}
.dsa-count{flex:0 0 auto;font-size:12px;font-variant-numeric:tabular-nums;color:var(--dsw-alias-label-secondary)}
.dsa-sub{font-size:12px;color:var(--dsw-alias-label-secondary)}
.dsa-list{display:flex;flex-direction:column;gap:4px;max-height:220px;margin:0;padding:8px 10px;overflow:auto;border-radius:8px;background:var(--dsw-alias-bg-layer-2);list-style:none}
.dsa-cmd{display:flex;gap:6px;align-items:flex-start;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.dsa-prompt{flex:0 0 auto;color:var(--dsw-alias-label-secondary);user-select:none}
.dsa-cmd-sudo .dsa-prompt{color:var(--dsw-alias-state-warn-primary)}
.dsa-note .dsa-code{color:var(--dsw-alias-label-secondary);font-style:italic}
.dsa-code{white-space:pre-wrap;word-break:break-word}
.dsa-error{font-size:12px;color:var(--dsw-alias-state-error-primary)}
.dsa-hint{font-size:12px;color:var(--dsw-alias-label-secondary)}
.dsa-row{display:flex;gap:8px;align-items:center}
.dsa-input{flex:1 1 auto;min-width:0;box-sizing:border-box;padding:7px 10px;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;outline:none}
.dsa-input:focus{border-color:var(--dsw-alias-brand-primary)}
.dsa-input:disabled{opacity:.6}
.dsa-button{flex:0 0 auto;box-sizing:border-box;padding:7px 14px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;cursor:pointer}
.dsa-button:hover:enabled{background:var(--dsw-alias-bg-layer-2)}
.dsa-button:disabled{opacity:.55;cursor:default}
.dsa-primary{border-color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-bg-base)}
.dsa-primary:hover:enabled{background:var(--dsw-alias-brand-primary);opacity:.9}
`

    /** Copy is bound in `apply`; the panel is created per page, so one binding is enough. */
    let t = (key) => key

    /** One pending request, published as the Session's pending interaction. */
    class PendingSudo {
      constructor(snapshot) {
        this.key = snapshot.id
        this.kind = NS
        this.sessionId = snapshot.sessionId
        this.snapshot = snapshot
      }
    }

    /** `mm:ss` for the remaining lifetime. */
    function formatClock(ms) {
      const total = Math.max(0, Math.ceil(ms / 1000))
      return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`
    }

    /** Password panel that replaces the composer while a request is pending. */
    function SudoPanel(props) {
      const pending = props.matched
      const snapshot = (pending && pending.snapshot) || {}
      const items = Array.isArray(snapshot.items) ? snapshot.items : []
      const passwordRequired = snapshot.passwordRequired !== false
      const [password, setPassword] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const [remaining, setRemaining] = React.useState(() => Math.max(0, (snapshot.expiresAt || 0) - Date.now()))
      const inputRef = React.useRef(null)

      React.useEffect(() => {
        const tick = () => setRemaining(Math.max(0, (snapshot.expiresAt || 0) - Date.now()))
        tick()
        const timer = window.setInterval(tick, 1000)
        return () => window.clearInterval(timer)
      }, [snapshot.expiresAt])

      React.useEffect(() => {
        const node = inputRef.current
        if (node === null || node === undefined) return
        try {
          node.focus()
        } catch {
          // focus is a convenience only
        }
      }, [])

      const submit = async (decision) => {
        if (busy) return
        setBusy(true)
        setError('')
        try {
          const body = { id: pending.key, decision }
          if (decision === 'approve' && password !== '') body.password = password
          const response = await fetch(RESPOND_ENDPOINT, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          })
          const payload = await response.json().catch(() => undefined)
          if (payload && payload.ok === true) {
            setPassword('')
            return
          }
          const code = payload && payload.error ? payload.error.code : undefined
          if (code === 'sudo-approve/invalid-password') {
            setPassword('')
            setError(t('invalidPassword'))
          } else if (code === 'sudo-approve/password-required') {
            setError(t('passwordRequired'))
          } else if (code === 'sudo-approve/stale') {
            setError(t('stale'))
          } else {
            setError(t('failed'))
          }
        } catch {
          setError(t('failed'))
        } finally {
          setBusy(false)
        }
      }

      const canApprove = !busy && (password !== '' || !passwordRequired)

      return h(
        'div',
        {
          className: 'dsa-panel',
          role: 'group',
          'aria-label': t('title'),
          onKeyDown: (event) => {
            if (event.key === 'Escape' && !busy) {
              event.preventDefault()
              submit('reject')
            }
          },
        },
        h('style', { dangerouslySetInnerHTML: { __html: CSS } }),
        h('div', { className: 'dsa-head' }, [
          h('span', { key: 'lock', className: 'dsa-lock', 'aria-hidden': true }, '🔒'),
          h('span', { key: 'title', className: 'dsa-title' }, t('title')),
          h('span', { key: 'count', className: 'dsa-count', title: t('remainingHint') }, formatClock(remaining)),
        ]),
        h('div', { className: 'dsa-sub' }, t('subtitle')),
        h(
          'ul',
          { className: 'dsa-list' },
          items.map((item, index) =>
            h(
              'li',
              {
                key: index,
                className: `dsa-cmd${item.sudo ? ' dsa-cmd-sudo' : ''}${item.note ? ' dsa-note' : ''}`,
              },
              h('span', { className: 'dsa-prompt', 'aria-hidden': true }, item.sudo ? '#' : '$'),
              h('code', { className: 'dsa-code' }, item.text),
            ),
          ),
        ),
        passwordRequired ? null : h('div', { className: 'dsa-hint' }, t('remembered')),
        error === '' ? null : h('div', { className: 'dsa-error', role: 'alert' }, error),
        h('div', { className: 'dsa-row' }, [
          h('input', {
            key: 'password',
            ref: inputRef,
            className: 'dsa-input',
            type: 'password',
            value: password,
            placeholder: t('password'),
            autoComplete: 'current-password',
            spellCheck: false,
            disabled: busy,
            onChange: (event) => setPassword(event.target.value),
            onKeyDown: (event) => {
              if (event.key !== 'Enter') return
              event.preventDefault()
              if (canApprove) submit('approve')
            },
          }),
          h(
            'button',
            { key: 'reject', type: 'button', className: 'dsa-button', disabled: busy, onClick: () => submit('reject') },
            t('reject'),
          ),
          h(
            'button',
            {
              key: 'approve',
              type: 'button',
              className: 'dsa-button dsa-primary',
              disabled: !canApprove,
              onClick: () => submit('approve'),
            },
            busy ? t('working') : t('approve'),
          ),
        ]),
      )
    }

    const inject = ['slots', 'locale', 'uiSession']

    function apply(ctx) {
      ctx.effect(() => ctx.locale.register(NS, { zh, en }), `${NS}: dictionaries`)
      t = ctx.locale.bind(NS)

      const publish = ctx.uiSession.registerPendingInteraction(() => 0)
      /** id → { pending, remove }; mirrors what the Host reports as pending. */
      const live = new Map()

      const drop = (id) => {
        const entry = live.get(id)
        if (entry === undefined) return
        try {
          entry.remove()
        } catch {
          // already gone
        }
        live.delete(id)
      }

      /** Reconcile the local pending set with the Host snapshot. */
      const sync = async () => {
        let response
        try {
          response = await fetch(PENDING_ENDPOINT, {
            credentials: 'same-origin',
            headers: { accept: 'application/json' },
          })
        } catch {
          return
        }
        if (!response.ok) return
        const payload = await response.json().catch(() => undefined)
        if (payload === undefined || payload.ok !== true) return
        const requests = Array.isArray(payload.value && payload.value.requests) ? payload.value.requests : []
        const seen = new Set()
        for (const snapshot of requests) {
          if (typeof snapshot.id !== 'string' || typeof snapshot.sessionId !== 'string') continue
          seen.add(snapshot.id)
          if (live.has(snapshot.id)) continue
          const pending = new PendingSudo(snapshot)
          const remove = publish(pending, async () => {})
          live.set(snapshot.id, { pending, remove })
        }
        for (const id of [...live.keys()]) {
          if (!seen.has(id)) drop(id)
        }
      }

      ctx.effect(() => {
        const timer = window.setInterval(() => {
          sync().catch(() => {})
        }, POLL_MS)
        sync().catch(() => {})
        return () => {
          window.clearInterval(timer)
          for (const id of [...live.keys()]) drop(id)
        }
      }, `${NS}: pending poll`)

      ctx.slots.inject('conversation.composer', () =>
        ctx.slots.register(
          {
            name: 'conversation.composer',
            priority: 5,
            locale: NS,
            select: ({ pendingInteraction }) => (pendingInteraction instanceof PendingSudo ? pendingInteraction : null),
          },
          SudoPanel,
        ),
      )
    }

    return { inject, apply }
  },
})
