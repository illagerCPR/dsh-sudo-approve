/**
 * Model-facing refusal texts.
 *
 * The model receives these as the pre-execute denial reason, so they are written
 * for an agent that must react sensibly rather than for a human reading a log.
 * @module dsh-sudo-approve/lib/messages
 */

export const MESSAGES = Object.freeze({
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
  /** The surface may not show everything, so it refuses instead of hiding a tail. */
  truncated: (lines, width, native = false, rowCap = 0) =>
    `sudo 审批：该命令超出${native ? '系统对话框' : '面板'}可完整显示的长度（最多 ${lines} 行、单行 ${width} 字符${native && rowCap > 0 ? `，按显示宽度折行后最多 ${rowCap} 显示行` : ''}），为避免你批准看不见的内容，已拒绝执行。请把命令拆成更短的几条分别执行；不要把需要授权的内容藏进脚本文件再调用——那样${native ? '对话框' : '面板'}同样看不到它。${native ? '系统对话框没有滚动条，所以这个上限比网页更小；需要长命令时把 passwordDialog 改成 browser。' : ''}`,
  /** `passwordDialog: native` was configured but this deployment cannot show one. */
  nativeUnavailable: (detail) =>
    `sudo 审批：配置要求用系统对话框接收密码（passwordDialog=native），但本部署不满足条件：${detail}。为避免在你看不到的界面上等待授权，已拒绝执行。请把 passwordDialog 改成 auto 或 browser，或先满足上面的条件。`,
  /** The approval record does not describe the call that is about to run. */
  mismatch: 'sudo 审批：批准记录与本次调用不匹配（会话、调用或命令内容已变化），已拒绝执行。请重新发起一次 sudo 调用。',
  /** `credential: timestamp` was configured but the cache cannot be reused here. */
  credential:
    'sudo 审批：配置要求用 sudo 时间戳缓存交付密码，但本机的 sudo 缓存无法被后续命令复用（无 tty 时按 tty/session 记账），已拒绝执行。请把 credential 改回 auto 或 askpass。',
})
