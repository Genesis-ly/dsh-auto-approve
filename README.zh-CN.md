# dsh-auto-approve

[English](README.md) | **中文**

把「写工作区外插件目录」这一类**重复且安全**的 shell 升级审批，改成确定性规则自动放行；其余一切仍然弹给你。

> 状态：**P1 可用**。规则引擎有 10 组单测覆盖（allow / pass 双向），首次上线建议先看一天 `audit.jsonl` 再决定是否放宽。

## 它解决什么

`workspace-write` 权限下，任何要写工作区之外的 shell 命令都必须人工审批。这台机器上的实际统计（15 个会话日志）：

- 审批请求 **69 次**，全部来自 shell 工具（`ops_bash` 66 / `pwsh` 3）
- 已决定的 **67 次全部是 `allowed-once`**，一次都没拒绝
- 理由清一色是「写入 `~/.dsh/plugins/...` / `~/.dsh/profiles/desktop/node_modules/...` 的插件文件」

也就是说这类弹窗的信息量是零：人来点 67 次 100% 同意。本插件用**可审计的规则**替代这部分人工点击。

## 触发链路（为什么插件要挂两个钩子）

1. 模型调用 shell 工具，参数里带 `sandbox_permissions`（比当前模式更宽）+ `justification`。
2. 工具内部走 `ctx.approval.request({ agent, callId, toolName, reason })` —— **审批请求不带工具参数**。
3. `dsh-user-approval` 把请求派发到 `approval/request` waterfall，应答者按顺序决定。

所以本插件：

| 钩子 | 作用 |
|---|---|
| `tools/pre-execute` | 记下 `callId → { name, arguments }`（只观察，原样 `next()`） |
| `approval/request` | `{ prepend: true }` 抢先应答：规则通过返回 `allowed-once`，否则 `next()` 交回 UI / Auto review |

## 判定规则

三种策略（`mode`），都先过一道**硬拦截**，再按策略决定。

### 硬拦截（任何策略都拦，交回人工）

整条命令（**先剥掉 heredoc 正文**，那是数据不是命令）不得出现：

删除类（`rm`/`del`/`rd`/`Remove-Item`/`dd`/`format`…）、网络（`curl`/`wget`/`Invoke-*`/`ssh`/`scp`…）、提权（`sudo`/`runas`）、系统变更（`reg`/`sc delete`/`schtasks`/`shutdown`/`taskkill`…）、包管理（`pip`/`npm`/`pnpm` install|publish…）、容器（`docker`/`kubectl`）、嵌套 shell（`bash -c`/`pwsh -c`…）、`node -e`/`python -c`、`eval`/`exec`/`xargs`、`source`、`find -delete/-exec`、裸设备写。

另外：动 **profile 配置**（`profiles/<x>/package.json`、`cordis.yml`、`cordis.patch.yml`）一律交人工——那几个文件决定下次启动加载什么代码，属于必须人确认的边界。

### 三种策略

| `mode` | 放行条件 | 历史 81 次请求回放 |
|---|---|---|
| `strict` | 能静态证明**全部写目标**落在 `allowRoots` 内 | 自动 3 / 人工 78 |
| `window` | `grantMinutes` 内有过一次人工批准（滑动续期） | 自动 48 / 人工 33 |
| **`denylist`（默认）** | 没触发硬拦截即可 | **自动 60 / 人工 21** |
| `both` | strict 命中，或 window 生效 | — |

`strict` 命中率低的原因：真实命令都是多行脚本（`set -e`、变量、`$(...)`、`python xxx.py`），静态不可证。

`pass`（交回人工）**不是拒绝**：请求原样交给下游应答者，UI 照常弹窗。

### 为什么这样定（数据）

15～19 个会话日志里共 81 次 shell 升级审批，全部 `ops_bash`/`pwsh`，已决定的 67 次 **100% 是 `allowed-once`**，理由清一色是写 `~/.dsh/plugins`、`~/.dsh/profiles/desktop/node_modules` 的插件文件。所以默认取 `denylist`：把"你已经点了 67 次全同意"的那类请求交出来，同时保留 16 类硬危险拦截。

## 配置

见 `cordis.patch.yml`，全部字段都有保守默认值。常用：

```yaml
- id: dsh-auto-approve
  config:
    mode: denylist        # strict | window | denylist | both
    grantMinutes: 10      # 仅 window/both 使用
    dryRun: true          # 只判断+审计，不给权限；用来先观察
    allowRoots: ['~/.dsh/plugins', '~/.dsh/profiles/*/node_modules']
```

## 审计

每次审批请求写一行 JSON 到 `~/.dsh/dsh-auto-approve/audit.jsonl`：

```json
{"at":"…","tool":"ops_bash","callId":"…","session":"…","decided":"allowed-once","via":"denylist","code":"denylist","reason":"no denied construct and no profile-config write","targets":[]}
```

`decided` 只有两种：`allowed-once`（自动放行）与 `pass-to-human`（交回 UI，`reason`/`code` 说明卡在哪条规则）。`via` 告诉你走的是哪条路径（`strict`/`window`/`denylist`）。

## 安装

```powershell
# 完全退出 DSH（含托盘）后
pwsh -NoProfile -File .\scripts\install.ps1    # 在本包目录执行
```

脚本做三件事：复制到 `~/.dsh/plugins/dsh-auto-approve` → `dsh plugin --profile desktop add link:…` → 确保 `dsh.profile.bundles` 含本包。重开 DSH 生效。

## 验证

1. 重开后让 agent 执行一条**需要写工作区外**的普通命令（带 `sandbox_permissions`），例如
   `mkdir -p ~/.dsh/plugins/_probe && echo ok > ~/.dsh/plugins/_probe/x.txt`
   —— **不应弹窗**，`audit.jsonl` 出现 `allowed-once` / `via: denylist`。
2. 反例：`rm -rf ~/.dsh/plugins/_probe` —— **应当弹窗**，审计是 `pass-to-human`。
3. 反例：任何改写 `~/.dsh/profiles/desktop/package.json` 的命令 —— **应当弹窗**。
4. 若第 1 步仍弹窗、且 `audit.jsonl` 完全没有新增行：说明本插件的应答者没排到最前（见下"已知边界"第 4 条），把 `audit.jsonl` 发我看。

## 回滚

把 profile patch 里 `enabled: false`（或 `mode: strict`），或从 `dsh.profile.bundles` 移除 `dsh-auto-approve`，重开即可。插件只新增应答者，不修改任何既有权限值；卸载后弹窗行为与装之前完全一致。

## 已知边界与风险

- **`denylist` 是字符串拦截，不是证明**。以下都能绕过：`python evil.py`、`node build.js`（脚本内容不可见）、`r''m -rf /`（引号拆词）、变量拼出的危险命令、base64 解码后执行。硬拦截只降低误放行的*表面*风险，不构成沙箱。
- 因此 `denylist` 的实际语义是「**承认 shell 升级免审**，但保留一批常见破坏性构造的黑名单」。它比切「完全权限」预设严格（后者零拦截），比 Auto review 弱（后者让模型读命令+上下文判断）。
- **`allowRoots` 只在 `strict`/`both` 下参与判定**；`denylist` 不检查写目标，所以不要以为它限制写入范围。
- 路径只做静态解析，不解析符号链接。
- **应答者排序**：桌面审批弹窗由 `dsh-api-remotes` 以 `push` 注册，且**不调 `next()`**。本插件用 `prepend: true`（`unshift`）排在它前面才能生效；若将来该实现改为 `prepend` 注册且加载更晚，本插件会失效——表现为弹窗恢复、审计无新增行。
- 只在 Host 同进程内生效；`run_code`（PTC）外层 transport 的副作用不经过本插件。
- 与 Auto review 的关系：两者都算自动应答。本插件 `prepend` 抢先，命中时不会触发 LLM 审查（省 token）；未命中时请求继续下发，Auto review / UI 照旧处理。注意**切到「自动审查」预设时沙箱已是完全权限，ops_bash 通常根本不会发起升级审批**，所以本插件主要工作在 `workspace-write` 会话里。
