# dsh-auto-approve

**English** | [中文](README.zh-CN.md)

A deterministic rule engine that removes one specific kind of approval popup in DSH: sandbox
escalations whose only purpose is to write files under the user's own plugin directory. Everything
else still goes to the normal approval UI (or Auto review).

## Why this exists

Under `workspace-write`, any shell command that writes outside the workspace needs approval. On one
real installation (15 session logs), 69 shell approval requests had been raised and all 67 decided
requests were `allowed-once` — every single one for writing `~/.dsh/plugins/...` or
`~/.dsh/profiles/*/node_modules/...`. That is a popup with no information: a human clicked "allow"
67 times in a row.

This plugin replaces exactly that class of clicks with auditable rules.

## How it hooks in

The approval request itself carries no tool arguments, so two hooks are needed:

| Hook | Purpose |
| --- | --- |
| `tools/pre-execute` | records `callId → { name, arguments }`, then calls `next()` unchanged |
| `approval/request` | `{ prepend: true }`: answers `allowed-once` when the rules pass, otherwise calls `next()` and the normal UI decides |

## Rules

Every request first passes a hard denylist. If anything matches — deletion commands
(`rm`, `del`, `Remove-Item`, `dd`, `format`), network tools (`curl`, `wget`, `ssh`, `scp`),
privilege escalation (`sudo`, `runas`), system changes (`reg`, `sc delete`, `schtasks`, `shutdown`,
`taskkill`), package managers (`pip`, `npm`, `pnpm install/publish`), containers, nested shells
(`bash -c`, `pwsh -c`), `node -e`, `python -c`, `eval`, `exec`, `xargs`, `find -delete/-exec`,
raw device writes — the request goes back to the human.

Writes to profile configuration (`profiles/*/package.json`, `cordis.yml`, `cordis.patch.yml`) are
always passed to the human: those files decide what code loads on the next start.

After that, one of four policies applies:

| `mode` | Approves when |
| --- | --- |
| `strict` | every write target is statically provable to be inside `allowRoots` |
| `window` | a human approved a request within `grantMinutes` (sliding) |
| `denylist` (default) | the command does not hit the hard denylist |
| `both` | `strict` matches, or `window` is active |

`pass` is not a rejection: the request is handed to the next responder and the UI shows normally.

## Configuration

```yaml
- id: dsh-auto-approve
  config:
    mode: denylist        # strict | window | denylist | both
    grantMinutes: 10      # window / both only
    dryRun: true          # decide + audit, never grant; use this first
    allowRoots: ['~/.dsh/plugins', '~/.dsh/profiles/*/node_modules']
```

## Audit

One JSON line per approval request in `~/.dsh/dsh-auto-approve/audit.jsonl`:

```json
{"at":"…","tool":"ops_bash","callId":"…","session":"…","decided":"allowed-once","via":"denylist","code":"denylist","reason":"no denied construct and no profile-config write","targets":[]}
```

`decided` is either `allowed-once` or `pass-to-human`; `via` names the path that decided.

## Install

```powershell
# Quit DSH completely (including the tray) first.
pwsh -NoProfile -File .\scripts\install.ps1
```

The script copies the package to `%USERPROFILE%\.dsh\plugins\dsh-auto-approve`, adds a `link:`
dependency, appends the package to `dsh.profile.bundles`, and backs up `package.json` first.
Restart DSH afterwards.

## Tests

```powershell
npm test        # 17 cases: rules 12 + plugin wiring 5
```

## Compatibility

DSH 0.2.2-rc.5, Windows 10/11, Node >= 20. No vendor file is modified; the plugin keeps working
after DSH and plugin updates.

## Security notes

- Start with `dryRun: true` and watch `audit.jsonl` for a day before enabling grants.
- The default `denylist` policy only grants when no dangerous construct is present; it never grants
  profile-configuration writes.
- Nothing is sent anywhere. The audit log is local.

## License

MIT — see [LICENSE](LICENSE). Security policy: [SECURITY.md](SECURITY.md).
