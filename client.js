/**
 * dsh-sudo-approve — Web client half.
 *
 * Polls the Host for a pending sudo confirmation and, while one exists, takes
 * over the current Session's composer with a password panel. Approving posts
 * the password once to the Host; it never becomes a chat message, so it never
 * reaches the model context or the session log. Rejecting may carry an optional
 * reason written by the user.
 *
 * Pure view code: no Harness Client package is imported, the card borrows the
 * composer geometry tokens so it lines up with the chat box, and every resource
 * is owned by `apply`.
 */

window.__ModuleLoader__.load({
  id: 'dsh-sudo-approve',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'dsh-sudo-approve'
    const PENDING_ENDPOINT = 'api/sudo-approve/pending'
    const RESPOND_ENDPOINT = 'api/sudo-approve/respond'
    const CONFIG_ENDPOINT = 'api/sudo-approve/config'
    const POLL_MS = 1500

    const zh = {
      title: '需要 sudo 授权',
      subtitle: '确认后会用该密码执行下面的命令；密码只提交给 Host，不会进入对话上下文或会话记录。',
      password: '输入登录密码',
      approve: '允许并执行',
      reject: '拒绝',
      reasonPlaceholder: '拒绝理由（可选，会转告智能体）',
      confirmReject: '确认拒绝',
      cancel: '取消',
      working: '处理中…',
      remembered: '已记住本次会话的密码：这次不用再输入，点「允许并执行」即以它放行。记住期间，任何能在本页面执行脚本的东西都可以在你不动手的情况下批准。',
      invalidPassword: '密码不正确，请重试。',
      passwordRequired: '请输入密码。',
      stale: '该请求已失效。',
      noInteraction: '这次批准没有被识别为页面上的真实操作，请重新点击一次。',
      failed: '提交失败，请重试。',
      remainingHint: '剩余时间',
      queueHint: '另有 {count} 笔排队',
      otherSession: '其他会话有 {count} 笔 sudo 待确认',
      jump: '切过去',
      collapse: '折叠',
      expand: '展开',
      settingsLabel: 'sudo 授权',
      settingsTitle: 'sudo 授权确认',
      settingsDesc: '智能体执行 sudo 时在聊天框弹出确认面板。这里的设置保存后立即生效，只影响之后发起的请求。',
      settingsEnabled: '启用拦截',
      settingsEnabledHint: '关闭后不再拦截 sudo 调用：插件仍然加载，但直接放行。',
      settingsRemember: '授权粒度',
      settingsRememberHint: '每次输入密码更安全。“本会话记住”之后批准不再需要密码，等于关掉密码这一环；密码只存在 Host 内存，会话结束或进程退出即清除。',
      rememberNever: '每次输入密码',
      rememberSession: '本会话记住',
      settingsTimeout: '面板超时',
      settingsTimeoutHint: '超过该秒数没有确认就拒绝执行。',
      settingsPresence: '页面在线窗口',
      settingsPresenceHint: '超过该秒数没有浏览器页面轮询，就认为页面已断开并直接拒绝。',
      settingsRemote: '允许远程部署接收密码',
      settingsRemoteHint: '开启后，通过非回环地址连接的浏览器也能提交密码；明文网络路径上有风险。',
      settingsReset: '恢复超时与在线窗口',
      settingsResetDone: '已恢复超时与在线窗口；安全开关（启用、授权粒度、凭据方式）不受影响',
      settingsSaved: '已保存',
      settingsSaving: '保存中…',
      settingsSaveFailed: '保存失败，请重试。',
      settingsLoadFailed: '读取配置失败，请刷新页面重试。',
      settingsFileOnly: '只读：请在配置文件里修改',
      unitSeconds: '秒',
    }

    const en = {
      title: 'sudo approval required',
      subtitle: 'Approving runs the commands below with this password. It is sent to the Host only and never enters the conversation or the session log.',
      password: 'Enter your login password',
      approve: 'Allow and run',
      reject: 'Reject',
      reasonPlaceholder: 'Rejection reason (optional, shared with the agent)',
      confirmReject: 'Confirm reject',
      cancel: 'Cancel',
      working: 'Working…',
      remembered: 'This session holds the password already, so this approval reuses it. While it is remembered, anything that can run script in this page can approve without you.',
      invalidPassword: 'Wrong password. Try again.',
      passwordRequired: 'Enter the password.',
      stale: 'This request is no longer pending.',
      noInteraction: 'The approval was not recognised as a real click on this page. Try again.',
      failed: 'Could not submit. Try again.',
      remainingHint: 'time left',
      queueHint: '{count} more waiting',
      otherSession: '{count} sudo approval waiting in another session',
      jump: 'Open',
      collapse: 'Collapse',
      expand: 'Expand',
      settingsLabel: 'sudo approval',
      settingsTitle: 'sudo approval',
      settingsDesc: 'The composer turns into a confirmation panel whenever the agent runs sudo. Settings apply immediately to new requests.',
      settingsEnabled: 'Intercept sudo',
      settingsEnabledHint: 'When off, sudo calls pass through untouched while the plugin stays loaded.',
      settingsRemember: 'Password scope',
      settingsRememberHint: 'Asking every time is safer. Remembering for the session means later approvals need no password at all; the secret lives in Host memory only and dies with the session or process.',
      rememberNever: 'Ask every time',
      rememberSession: 'Remember for this session',
      settingsTimeout: 'Panel timeout',
      settingsTimeoutHint: 'An unanswered request is rejected after this many seconds.',
      settingsPresence: 'Page presence window',
      settingsPresenceHint: 'With no page poll for this many seconds, requests are rejected outright.',
      settingsRemote: 'Accept passwords from remote deployments',
      settingsRemoteHint: 'Lets a browser connected over a non-loopback address submit the password, which is risky on a plaintext path.',
      settingsReset: 'Restore timing defaults',
      settingsResetDone: 'Timing defaults restored; the security switches (enabled, password scope, credential) are untouched',
      settingsSaved: 'Saved',
      settingsSaving: 'Saving…',
      settingsSaveFailed: 'Could not save. Try again.',
      settingsLoadFailed: 'Could not read the settings. Refresh the page and retry.',
      settingsFileOnly: 'Read-only: change it in the config file',
      unitSeconds: 's',
    }

    const CSS = `
.dsa-seat{box-sizing:border-box;display:flex;flex-direction:column;align-items:center;width:100%;padding:8px var(--dsh-composer-side-clearance,16px) 12px}
.dsa-panel{box-sizing:border-box;display:flex;flex-direction:column;width:100%;max-width:var(--dsh-composer-card-max-width,min(calc(100% - 32px),952px));overflow:hidden;border:1px solid var(--dsw-alias-state-warn-secondary);border-radius:var(--dsw-radius-panel,28px);background:var(--dsw-specific-input-major,var(--dsw-alias-bg-layer-1));box-shadow:var(--dsw-elevation-soft);color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.55}
.dsa-strip{display:flex;align-items:center;gap:8px;padding:10px 18px;background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-primary);font-size:13px;line-height:20px}
.dsa-lock{font-size:14px;line-height:1}
.dsa-title{flex:1 1 auto;font-weight:600}
.dsa-count{flex:0 0 auto;font-size:12px;font-variant-numeric:tabular-nums;opacity:.85}
.dsa-queue{flex:0 0 auto;font-size:12px;line-height:18px;padding:0 8px;border-radius:999px;white-space:nowrap;font-weight:600;color:inherit;background:transparent;border:1px solid currentColor;background:color-mix(in srgb,currentColor 14%,transparent);border-color:color-mix(in srgb,currentColor 38%,transparent)}
.dsa-dock{display:inline-flex;align-items:center;gap:8px;margin:2px 0;padding:3px 4px 3px 10px;border-radius:999px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l1)}
.dsa-dock-dot{width:6px;height:6px;flex:0 0 auto;border-radius:999px;background:var(--dsw-alias-state-warn-primary)}
.dsa-dock-text{white-space:nowrap}
.dsa-dock-jump{flex:0 0 auto;display:inline-flex;align-items:center;height:20px;padding:0 10px;border-radius:999px;font:inherit;font-weight:600;cursor:pointer;white-space:nowrap;color:var(--dsw-alias-brand-primary);background:transparent;border:1px solid currentColor;background:color-mix(in srgb,var(--dsw-alias-brand-primary) 12%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-brand-primary) 34%,transparent);transition:background-color .15s ease,border-color .15s ease}
.dsa-dock-jump:hover{background:color-mix(in srgb,var(--dsw-alias-brand-primary) 20%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-brand-primary) 52%,transparent)}
.dsa-dock-jump:active{background:color-mix(in srgb,var(--dsw-alias-brand-primary) 26%,transparent)}
.dsa-dock-jump:focus-visible{outline:2px solid color-mix(in srgb,var(--dsw-alias-brand-primary) 45%,transparent);outline-offset:1px}
.dsa-toggle{flex:0 0 auto;display:grid;place-items:center;box-sizing:border-box;width:22px;height:22px;padding:0;border:0;border-radius:999px;background:transparent;color:inherit;font-size:11px;line-height:1;cursor:pointer;opacity:.8}
.dsa-toggle:hover:enabled{background:var(--dsw-alias-interactive-bg-hover);opacity:1}
.dsa-toggle:disabled{opacity:.45;cursor:default}
.dsa-collapsed{min-height:var(--dsa-collapsed-min-height,96px);justify-content:center}
.dsa-collapsed .dsa-strip{flex:1 1 auto}
.dsa-body{display:flex;flex-direction:column;gap:10px;padding:14px 18px 4px}
.dsa-sub{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.dsa-list{display:flex;flex-direction:column;gap:6px;max-height:200px;margin:0;padding:10px 12px;overflow:auto;border-radius:12px;background:var(--dsw-alias-bg-layer-2);list-style:none}
.dsa-cmd{display:flex;gap:6px;align-items:flex-start;font-family:var(--ds-font-family-code,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:12px;line-height:20px}
.dsa-prompt{flex:0 0 auto;color:var(--dsw-alias-label-secondary);user-select:none}
.dsa-cmd-sudo .dsa-prompt{color:var(--dsw-alias-state-warn-primary)}
.dsa-note .dsa-code{color:var(--dsw-alias-label-secondary);font-style:italic}
.dsa-code{white-space:pre-wrap;word-break:break-word}
.dsa-hint{font-size:12px;color:var(--dsw-alias-label-secondary)}
.dsa-hint-risk{color:var(--dsw-alias-state-warn-primary)}
.dsa-error{font-size:12px;color:var(--dsw-alias-state-error-primary)}
.dsa-actions{display:flex;align-items:center;gap:8px;padding:12px 18px 16px}
.dsa-spacer{flex:1 1 auto}
.dsa-input{box-sizing:border-box;padding:8px 12px;border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;outline:none}
.dsa-input:focus{border-color:var(--dsw-alias-brand-primary)}
.dsa-input:disabled{opacity:.6}
.dsa-password{flex:0 0 auto;width:240px}
.dsa-reason{flex:1 1 auto;min-width:0}
.dsa-button{flex:0 0 auto;box-sizing:border-box;padding:8px 16px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;cursor:pointer}
.dsa-button:hover:enabled{background:var(--dsw-alias-bg-layer-2)}
.dsa-button:disabled{opacity:.55;cursor:default}
.dsa-danger:hover:enabled{background:var(--dsw-alias-interactive-bg-hover-danger,var(--dsw-alias-bg-layer-2));color:var(--dsw-alias-state-error-primary);border-color:transparent}
.dsa-primary{border-color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-bg-base)}
.dsa-primary:hover:enabled{opacity:.9}
`

    const SETTINGS_CSS = `
.dsa-set{display:flex;flex-direction:column;max-width:640px;padding:4px 0 28px;color:var(--dsw-alias-label-primary)}
.dsa-set-head{margin-bottom:6px}
.dsa-set-title{margin:0;font-size:16px;font-weight:600;line-height:24px}
.dsa-set-desc{margin:4px 0 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.dsa-set-row{display:flex;align-items:flex-start;gap:16px;padding:14px 0;border-top:1px solid var(--dsw-alias-border-l1)}
.dsa-set-head+.dsa-set-row{border-top:none}
.dsa-set-ro{display:flex;flex-direction:column;align-items:flex-end;gap:2px;text-align:right}
.dsa-set-ro-value{font-weight:600;color:var(--dsw-alias-label-primary)}
.dsa-set-main{flex:1 1 auto;min-width:0}
.dsa-set-name{font-size:13px;line-height:20px}
.dsa-set-hint{margin-top:2px;font-size:12px;line-height:17px;color:var(--dsw-alias-label-secondary)}
.dsa-set-control{display:flex;flex:0 0 auto;align-items:center;gap:6px;padding-top:1px}
.dsa-switch{position:relative;box-sizing:border-box;width:38px;height:22px;padding:0;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:var(--dsw-alias-bg-layer-2);cursor:pointer;transition:background .15s,border-color .15s}
.dsa-switch[aria-checked=true]{border-color:var(--dsw-alias-brand-primary);background:var(--dsw-alias-brand-primary)}
.dsa-switch:disabled{opacity:.55;cursor:default}
.dsa-knob{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--dsw-alias-bg-base);box-shadow:0 1px 2px #00000033;transition:transform .15s}
.dsa-switch[aria-checked=true] .dsa-knob{transform:translateX(16px)}
.dsa-seg{display:flex;overflow:hidden;border:1px solid var(--dsw-alias-border-l1);border-radius:10px}
.dsa-seg button{box-sizing:border-box;padding:6px 12px;border:0;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;cursor:pointer}
.dsa-seg button[aria-pressed=true]{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary)}
.dsa-seg button:disabled{opacity:.55;cursor:default}
.dsa-num{box-sizing:border-box;width:88px;padding:6px 10px;border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:12px;text-align:right}
.dsa-num:focus{border-color:var(--dsw-alias-brand-primary);outline:none}
.dsa-set-foot{display:flex;align-items:center;gap:12px;margin-top:18px;padding-top:14px;border-top:1px solid var(--dsw-alias-border-l1)}
.dsa-set-status{flex:1 1 auto;min-width:0;font-size:12px;line-height:17px;color:var(--dsw-alias-label-secondary);word-break:break-all}
.dsa-set-status[data-error=true]{color:var(--dsw-alias-state-error-primary)}
.dsa-link{box-sizing:border-box;padding:6px 12px;border:1px solid var(--dsw-alias-border-l2);border-radius:10px;background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:12px;cursor:pointer}
.dsa-link:hover:enabled{background:var(--dsw-alias-bg-layer-2)}
.dsa-link:disabled{opacity:.55;cursor:default}
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

    /**
     * Latest pending state from the Host poll: which Session owns the request on
     * screen, and how many wait behind it. A published pending snapshot is frozen
     * when it appears, so the panel badge and the cross-session notice read this
     * instead of the snapshot they were handed.
     */
    const pendingState = { sessionId: undefined, waiting: 0, listeners: new Set() }
    const readPendingState = () => pendingState
    const setPendingState = (sessionId, waiting) => {
      if (pendingState.sessionId === sessionId && pendingState.waiting === waiting) return
      pendingState.sessionId = sessionId
      pendingState.waiting = waiting
      for (const listener of [...pendingState.listeners]) listener()
    }
    const subscribePendingState = (listener) => {
      pendingState.listeners.add(listener)
      return () => {
        pendingState.listeners.delete(listener)
      }
    }
    /** Set by `apply`; opens the Session view that owns a request. */
    let openSessionView = () => {}

    /** `mm:ss` for the remaining lifetime. */
    function formatClock(ms) {
      const total = Math.max(0, Math.ceil(ms / 1000))
      return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`
    }

    /**
     * Dock entry for a request that belongs to another Session: the panel itself
     * only renders in the Session that owns the request, so without this a queued
     * approval is invisible until the user happens to switch there.
     */
    function OtherSessionNotice(props) {
      const [state, setState] = React.useState(readPendingState)
      React.useEffect(() => subscribePendingState(() => setState(readPendingState())), [])
      const owner = state.sessionId
      // No Session view (the inert state) or the owner is on screen: nothing to say.
      if (owner === undefined || props.sessionId === undefined || owner === props.sessionId) return null
      return h('div', { className: 'dsa-dock' }, [
        h('span', { key: 'dot', className: 'dsa-dock-dot', 'aria-hidden': true }),
        h('span', { key: 'text', className: 'dsa-dock-text' }, t('otherSession', { count: state.waiting + 1 })),
        h(
          'button',
          {
            key: 'jump',
            type: 'button',
            className: 'dsa-dock-jump',
            onClick: () => {
              try {
                openSessionView(owner)
              } catch {
                // the workspace service is optional; the text is still useful
              }
            },
          },
          t('jump'),
        ),
      ])
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
      const [rejecting, setRejecting] = React.useState(false)
      const [collapsed, setCollapsed] = React.useState(false)
      const [reason, setReason] = React.useState('')
      const [remaining, setRemaining] = React.useState(() => Math.max(0, (snapshot.expiresAt || 0) - Date.now()))
      const passwordRef = React.useRef(null)
      const reasonRef = React.useRef(null)
      const composing = React.useRef(false)

      React.useEffect(() => {
        const tick = () => setRemaining(Math.max(0, (snapshot.expiresAt || 0) - Date.now()))
        tick()
        const timer = window.setInterval(tick, 1000)
        return () => window.clearInterval(timer)
      }, [snapshot.expiresAt])

      // A new request always starts expanded and empty: a collapsed panel must
      // never hide a freshly arrived password prompt, and a password typed for
      // the previous request must not carry over to the next one in the queue.
      React.useEffect(() => {
        setCollapsed(false)
        setPassword('')
        setError('')
        setRejecting(false)
        setReason('')
      }, [pending && pending.key])

      const [waiting, setWaiting] = React.useState(() => readPendingState().waiting)
      React.useEffect(() => subscribePendingState(() => setWaiting(readPendingState().waiting)), [])

      // Focus follows the mode: the password field normally, the reason field
      // once the user starts a rejection.
      React.useEffect(() => {
        const node = rejecting ? reasonRef.current : passwordRef.current
        if (node === null || node === undefined) return
        try {
          node.focus()
        } catch {
          // focus is a convenience only
        }
      }, [rejecting, pending && pending.key])

      const closeReject = () => {
        if (busy) return
        setRejecting(false)
        setReason('')
        setError('')
      }

      /**
       * Report a gesture before approving.
       *
       * The Host snapshots "did a gesture happen lately" before it records the
       * request that asks, so an approval carrying its own claim would be judged
       * against a fact it had just written. Sending the report first keeps the
       * order honest; the claim itself is still this page's word, which is why
       * the security switches stay file-only (see SECURITY.md).
       */
      const reportGesture = async () => {
        try {
          await fetch(`${PENDING_ENDPOINT}?state=visible&interaction=1`, {
            credentials: 'same-origin',
            headers: { accept: 'application/json' },
          })
        } catch {
          // A report that fails to send is not fatal: the Host may refuse, and
          // the error message tells the user to click again.
        }
      }

      const submit = async (decision) => {
        if (busy) return
        setBusy(true)
        setError('')
        try {
          const body = { id: pending.key, decision }
          // An approval has to follow a gesture the page reported first; the
          // Host no longer lets the approval request supply its own evidence.
          const flags = decision === 'approve' ? '?state=visible&interaction=1' : ''
          if (decision === 'approve') {
            await reportGesture()
            body.interaction = true
            if (password !== '') body.password = password
          } else {
            const trimmed = reason.trim()
            if (trimmed !== '') body.reason = trimmed
          }
          const response = await fetch(`${RESPOND_ENDPOINT}${flags}`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          })
          const payload = await response.json().catch(() => undefined)
          if (payload && payload.ok === true) {
            setPassword('')
            setReason('')
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
          } else if (code === 'sudo-approve/no-interaction') {
            setError(t('noInteraction'))
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
      const enterWithoutComposition = (event) =>
        event.key === 'Enter' &&
        composing.current === false &&
        !(event.nativeEvent && event.nativeEvent.isComposing) &&
        event.keyCode !== 229

      return h(
        'div',
        { className: 'dsa-seat' },
        h(
          'div',
          {
            className: collapsed ? 'dsa-panel dsa-collapsed' : 'dsa-panel',
            role: 'group',
            'aria-label': t('title'),
            onKeyDown: (event) => {
              if (event.key !== 'Escape' || busy) return
              event.preventDefault()
              if (collapsed) setCollapsed(false)
              else if (rejecting) closeReject()
              else setRejecting(true)
            },
          },
          h('div', { className: 'dsa-strip' }, [
            h('span', { key: 'lock', className: 'dsa-lock', 'aria-hidden': true }, '🔒'),
            h('span', { key: 'title', className: 'dsa-title' }, t('title')),
            waiting > 0
              ? h('span', { key: 'queue', className: 'dsa-queue' }, t('queueHint', { count: waiting }))
              : null,
            h('span', { key: 'count', className: 'dsa-count', title: t('remainingHint') }, formatClock(remaining)),
            h(
              'button',
              {
                key: 'toggle',
                type: 'button',
                className: 'dsa-toggle',
                title: collapsed ? t('expand') : t('collapse'),
                'aria-label': collapsed ? t('expand') : t('collapse'),
                'aria-expanded': !collapsed,
                onClick: () => setCollapsed((value) => !value),
              },
              collapsed ? '\u25be' : '\u25b4',
            ),
          ]),
          collapsed ? null : h('div', { className: 'dsa-body' }, [
            h('div', { key: 'sub', className: 'dsa-sub' }, t('subtitle')),
            h(
              'ul',
              { key: 'list', className: 'dsa-list' },
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
            passwordRequired || rejecting ? null : h('div', { key: 'hint', className: 'dsa-hint dsa-hint-risk' }, t('remembered')),
            error === '' ? null : h('div', { key: 'error', className: 'dsa-error', role: 'alert' }, error),
          ]),
          collapsed
            ? null
            : rejecting
            ? h('div', { className: 'dsa-actions' }, [
                h('input', {
                  key: 'reason',
                  ref: reasonRef,
                  className: 'dsa-input dsa-reason',
                  type: 'text',
                  value: reason,
                  placeholder: t('reasonPlaceholder'),
                  maxLength: 200,
                  spellCheck: false,
                  disabled: busy,
                  onChange: (event) => setReason(event.target.value),
                  onCompositionStart: () => {
                    composing.current = true
                  },
                  onCompositionEnd: () => {
                    composing.current = false
                  },
                  onKeyDown: (event) => {
                    if (!enterWithoutComposition(event)) return
                    event.preventDefault()
                    submit('reject')
                  },
                }),
                h('div', { key: 'spacer', className: 'dsa-spacer' }),
                h(
                  'button',
                  { key: 'cancel', type: 'button', className: 'dsa-button', disabled: busy, onClick: closeReject },
                  t('cancel'),
                ),
                h(
                  'button',
                  {
                    key: 'confirm',
                    type: 'button',
                    className: 'dsa-button dsa-danger',
                    disabled: busy,
                    onClick: () => submit('reject'),
                  },
                  busy ? t('working') : t('confirmReject'),
                ),
              ])
            : h('div', { className: 'dsa-actions' }, [
                h('input', {
                  key: 'password',
                  ref: passwordRef,
                  className: 'dsa-input dsa-password',
                  type: 'password',
                  value: password,
                  placeholder: t('password'),
                  autoComplete: 'current-password',
                  spellCheck: false,
                  disabled: busy,
                  onChange: (event) => setPassword(event.target.value),
                  onCompositionStart: () => {
                    composing.current = true
                  },
                  onCompositionEnd: () => {
                    composing.current = false
                  },
                  onKeyDown: (event) => {
                    if (!enterWithoutComposition(event)) return
                    event.preventDefault()
                    if (canApprove) submit('approve')
                  },
                }),
                h('div', { key: 'spacer', className: 'dsa-spacer' }),
                h(
                  'button',
                  { key: 'reject', type: 'button', className: 'dsa-button', disabled: busy, onClick: () => setRejecting(true) },
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
        ),
      )
    }

    /** Settings page: the same knobs as the Loader config, stored by the Host. */
    function SettingsPanel() {
      const [snapshot, setSnapshot] = React.useState(undefined)
      const [status, setStatus] = React.useState('')
      const [failed, setFailed] = React.useState(false)
      const [busy, setBusy] = React.useState(false)

      const load = React.useCallback(async () => {
        try {
          const response = await fetch(CONFIG_ENDPOINT, {
            credentials: 'same-origin',
            headers: { accept: 'application/json' },
          })
          const payload = await response.json().catch(() => undefined)
          if (payload && payload.ok === true) {
            setSnapshot(payload.value)
            return
          }
        } catch {
          // reported below
        }
        setFailed(true)
        setStatus(t('settingsLoadFailed'))
      }, [])

      React.useEffect(() => {
        load().catch(() => {})
      }, [load])

      const send = async (payload, note) => {
        if (busy) return
        setBusy(true)
        setFailed(false)
        setStatus(t('settingsSaving'))
        try {
          const response = await fetch(CONFIG_ENDPOINT, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          })
          const body = await response.json().catch(() => undefined)
          if (body && body.ok === true) {
            setSnapshot(body.value)
            setStatus(note)
            return
          }
        } catch {
          // reported below
        }
        setFailed(true)
        setStatus(t('settingsSaveFailed'))
      }

      const values = (snapshot && snapshot.values) || {}
      const limits = (snapshot && snapshot.limits) || { timeoutMs: [5000, 900000], presenceWindowMs: [2000, 300000] }
      const ready = snapshot !== undefined
      const disabled = !ready || busy

      const commitSeconds = (raw, field, bounds) => {
        const seconds = Number(raw)
        if (!Number.isFinite(seconds) || seconds <= 0) return
        const low = Math.ceil(bounds[0] / 1000)
        const high = Math.floor(bounds[1] / 1000)
        const next = Math.min(Math.max(Math.round(seconds), low), high)
        if (next * 1000 === values[field]) return
        send({ patch: { [field]: next * 1000 } }, t('settingsSaved'))
      }

      const row = (name, hint, control) => [
        h('div', { key: 'main', className: 'dsa-set-main' }, [
          h('div', { key: 'name', className: 'dsa-set-name' }, name),
          hint === '' ? null : h('div', { key: 'hint', className: 'dsa-set-hint' }, hint),
        ]),
        h('div', { key: 'control', className: 'dsa-set-control' }, control),
      ]

      const readonlyRow = (key, name, hint, valueText) =>
        h('div', { key, className: 'dsa-set-row' },
          row(
            name,
            hint,
            h('div', { className: 'dsa-set-ro' }, [
              h('span', { key: 'value', className: 'dsa-set-ro-value' }, valueText),
              h('span', { key: 'note', className: 'dsa-set-hint' }, t('settingsFileOnly')),
            ]),
          ),
        )

      const numberRow = (key, name, hint, field, bounds) =>
        h('div', { key, className: 'dsa-set-row' },
          row(name, hint, [
            h('input', {
              key: `value-${values[field]}`,
              className: 'dsa-num',
              type: 'number',
              min: Math.ceil(bounds[0] / 1000),
              max: Math.floor(bounds[1] / 1000),
              defaultValue: ready ? Math.round(values[field] / 1000) : '',
              disabled,
              'aria-label': name,
              onKeyDown: (event) => {
                if (event.key !== 'Enter') return
                event.currentTarget.blur()
              },
              onBlur: (event) => commitSeconds(event.target.value, field, bounds),
            }),
            h('span', { key: 'unit', className: 'dsa-set-hint' }, t('unitSeconds')),
          ]),
        )

      const rememberRow = readonlyRow(
        'remember',
        t('settingsRemember'),
        t('settingsRememberHint'),
        values.remember === 'session' ? t('rememberSession') : t('rememberNever'),
      )

      const footer =
        status !== ''
          ? status
          : ready
            ? `build ${snapshot.build} · ${snapshot.store}`
            : ''

      return h(
        'div',
        { className: 'dsa-set' },
        h('div', { className: 'dsa-set-head' }, [
          h('h2', { key: 'title', className: 'dsa-set-title' }, t('settingsTitle')),
          h('p', { key: 'desc', className: 'dsa-set-desc' }, t('settingsDesc')),
        ]),
        readonlyRow(
          'enabled',
          t('settingsEnabled'),
          t('settingsEnabledHint'),
          values.enabled === false ? '—' : '✓',
        ),
        rememberRow,
        numberRow('timeout', t('settingsTimeout'), t('settingsTimeoutHint'), 'timeoutMs', limits.timeoutMs),
        numberRow(
          'presence',
          t('settingsPresence'),
          t('settingsPresenceHint'),
          'presenceWindowMs',
          limits.presenceWindowMs,
        ),
        readonlyRow(
          'remote',
          t('settingsRemote'),
          t('settingsRemoteHint'),
          values.allowRemoteDeployment === true ? '✓' : '—',
        ),
        h('div', { className: 'dsa-set-foot' }, [
          h('div', { key: 'status', className: 'dsa-set-status', 'data-error': failed, title: footer }, footer),
          h(
            'button',
            {
              key: 'reset',
              type: 'button',
              className: 'dsa-link',
              disabled,
              onClick: () => send({ reset: true }, t('settingsResetDone')),
            },
            t('settingsReset'),
          ),
        ]),
      )
    }

    const inject = ['slots', 'locale', 'uiSession']

    function apply(ctx) {
      ctx.effect(() => ctx.locale.register(NS, { zh, en }), `${NS}: dictionaries`)
      t = ctx.locale.bind(NS)

      // The dock notice renders in Sessions that have no panel mounted, so the
      // stylesheet cannot live inside a component: it goes on the document once.
      ctx.effect(() => {
        const node = document.createElement('style')
        node.dataset.dshSudoApprove = ''
        node.textContent = `${CSS}\n${SETTINGS_CSS}`
        document.head.append(node)
        return () => {
          node.remove()
        }
      }, `${NS}: styles`)

      const publish = ctx.uiSession.registerPendingInteraction(() => 0)
      /** id → { pending, remove }; mirrors what the Host reports as pending. */
      const live = new Map()

      // Presence: the Host refuses to open a panel for a page that never says it
      // is on screen, and an approval has to carry a real gesture. Both are
      // claims made by this page, so they are a speed bump, not a proof.
      let gestureAt = 0
      ctx.effect(() => {
        const onGesture = () => {
          gestureAt = Date.now()
        }
        const options = { capture: true, passive: true }
        document.addEventListener('pointerdown', onGesture, options)
        document.addEventListener('keydown', onGesture, options)
        document.addEventListener('focusin', onGesture, options)
        return () => {
          document.removeEventListener('pointerdown', onGesture, options)
          document.removeEventListener('keydown', onGesture, options)
          document.removeEventListener('focusin', onGesture, options)
        }
      }, `${NS}: presence gestures`)

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
          const visible = document.visibilityState === 'visible'
          const interacted = gestureAt !== 0 && Date.now() - gestureAt < 5_000
          const query = `?state=${visible ? 'visible' : 'hidden'}${interacted ? '&interaction=1' : ''}`
          response = await fetch(`${PENDING_ENDPOINT}${query}`, {
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
        const waiting = payload.value && Number.isFinite(payload.value.waiting) ? payload.value.waiting : 0
        const head = requests[0]
        setPendingState(typeof head?.sessionId === 'string' ? head.sessionId : undefined, waiting)
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

      openSessionView = (sessionId) => ctx.get('uiWorkspace')?.openSession?.(sessionId)

      ctx.slots.inject('conversation.composer.dock', () =>
        ctx.slots.register(
          {
            name: 'conversation.composer.dock',
            id: 'sudo-approve-elsewhere',
            order: 20,
            locale: NS,
          },
          OtherSessionNotice,
        ),
      )

      ctx.slots.inject('settings.section', () =>
        ctx.slots.register(
          {
            name: 'settings.section',
            id: 'sudo-approve',
            order: 40,
            label: () => t('settingsLabel'),
          },
          SettingsPanel,
        ),
      )
    }

    return { inject, apply }
  },
})
