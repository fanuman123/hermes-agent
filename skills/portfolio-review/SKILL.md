---
name: portfolio-review
description: Review trading portfolios without writes.
version: 1.0.0
author: Fanu + Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [portfolio, operator-review, kraken-bot, openclaw-decommission, safety, read-only]
    category: domain
    related_skills: [hermes-agent, runtime-service-audit]
---

# Portfolio Review Skill

This skill runs a bounded, Hermes-native portfolio review using read-only
source and artifact inspection. The goal is situational awareness: summarize
portfolio/risk posture, surface verification gaps, and recommend safe operator
next steps.

Hermes is the operator/control-plane layer. Kraken Bot V2 remains the only live
execution authority. OpenClaw is legacy advisory/reporting context only and may
be used only for comparison.

## When to Use

Use this skill when the user asks for:

- A portfolio review.
- Current trading posture, exposure, holdings, or risk summary.
- A read-only sanity check of Kraken Bot V2 runtime artifacts.
- Paper/live separation review.
- A Hermes-native replacement for legacy OpenClaw operator reporting.
- Assumptions and verification gaps before making trading-system decisions.

Do not use this skill for:

- Placing, cancelling, replacing, or replaying orders.
- Writing Kraken Bot V2 overrides, promotion files, configs, runtime state, or
  generated reports into trading repos.
- Editing `.env`, launchd plists, live bot code, risk gates, execution config,
  safety gates, or exchange-write configuration.
- Deleting, migrating, or modifying OpenClaw.
- Long autonomous investigations, recursive repo crawling, or filesystem-wide
  scans.

## Required Safety Boundary

Always preserve these boundaries:

1. **Kraken Bot V2 is the only live execution authority.**
2. **Hermes output is advisory/operator-facing only.**
3. **OpenClaw is comparison-only legacy advisory context.**
4. **No override writes.**
5. **No config mutation.**
6. **No `.env` edits or secret reads.**
7. **No launchd changes.**
8. **No live order actions.**
9. **No direct replacement of Kraken Bot V2 risk or promotion logic.**

If the operator asks for a risky action, stop and ask for explicit approval
with a narrow scope.

## Prerequisites

- User has explicitly requested a portfolio review.
- Hermes is running in a workspace where the relevant repositories are locally
  available.
- Any required runtime artifacts are read through the allowlist in this file or
  through a narrower user-provided path.
- Secrets are never opened. Do not inspect `.env`, launchd plists, API keys,
  wallet seeds, account credentials, or exchange tokens.

## CURRENT_STATE-First Procedure

1. Identify the repository scope.
   - Hermes workspace docs normally live in the Hermes repo.
   - Kraken Bot V2 runtime/source should be inspected only if required for the
     review.
   - OpenClaw should be treated as legacy reference only.
2. Check git status for referenced repos before edits or source inspection
   summaries.
3. Read context in this order where present:
   - `docs/AI_OPERATOR_RULES.md`
   - `docs/CURRENT_STATE.md`
   - `docs/LATEST_AGENT_LAB.md`
   - `docs/task_context/*`
   - `AGENTS.md` and workspace adapter docs
4. If generated state appears stale, stop and tell the operator exactly which
   command to rerun:
   - `make current-state`
   - `make task-context/prompt-context`
   - `make semantic-index PROJECT=<project>`
5. Do not rely on generated summaries alone if source files or runtime
   artifacts contradict them.

## Bounded Inspection Rules

Default bounds:

- Inspect at most 8 files initially.
- Use repo-scoped paths only.
- No filesystem-wide scans.
- No recursive repo crawling.
- Avoid logs unless explicitly required.
- Avoid runtime artifacts unless the review question requires current holdings,
  balances, open orders, recent decisions, or risk posture.
- Prefer targeted reads over broad searches.

If more context is necessary, state what is missing and ask for scope
expansion.

## How to Run

1. Confirm scope:
   - Kraken Bot V2: read-only source and artifact review.
   - OpenClaw: comparison-only advisory context.
   - Hermes: runner/checklist only.
2. Use `terminal` only for read-only commands such as status, diff names, log
   display, narrow file listing, checksum, timestamp, and tests that do not
   write to trading repos.
3. Use `read_file` for specific source files and artifacts after checking they
   are in the allowlist.
4. Do not use `patch`, editor tools, deploy commands, service managers, package
   installers, migration commands, cleanup commands, or exchange/client write
   APIs.
5. Put final analysis in the chat response unless the user explicitly asks for
   an output file outside the trading repos.

## Quick Reference

Allowed Hermes tools:

- `terminal` for read-only shell commands.
- `read_file` for allowlisted source and artifact files.
- `search_files` only with narrow, non-recursive targets.

Disallowed actions:

- `patch` or any file-editing tool against OpenClaw or Kraken Bot V2.
- Commands that create, move, delete, append, truncate, lock, migrate, deploy,
  install, restart, repair state, or submit/cancel exchange orders.
- Reading `.env`, launchd files, credential stores, private keys, or secrets.
- Any mutation of execution, risk, provenance, promotion, override, or safety
  gate paths.

## Kraken Bot V2 Read-Only Artifact Allowlist

Only the following Kraken Bot V2 paths may be read as runtime artifacts during
this process. Prefer the narrowest file or date partition that answers the
question.

- `logs/`
- `reports/`
- `artifacts/`
- `runs/`
- `data/`
- `data/state.json`
- `data/portfolio_snapshot.json`
- `data/open_orders_snapshot.json`
- `data/telegram_status.json`
- `state/portfolio*`
- `state/positions*`
- `state/balances*`
- `state/exposure*`
- `state/risk*`
- `state/paper*`
- `state/live*`
- `state/orders*` only for read-only historical inspection.
- `state/trades*` only for read-only historical inspection.
- `snapshots/`
- `metrics/`
- `backtests/`
- `paper/`
- `live/` only for read-only observations, never mutation.

Never read or write:

- `.env`, `.env.*`, credentials, keys, secrets, launchd files, deployment files.
- Files that hold active override, promotion, execution, safety-gate, or
  exchange-write configuration unless the user explicitly names a read-only
  source file and the task requires source verification.

## Procedure

1. Record the repositories and absolute paths in scope.
2. Run read-only dirty-state checks before any review:
   - `git -C <repo> status --short`
   - `git -C <repo> diff --name-only`
3. Identify the exact source files needed for interpretation before reading
   artifacts. Keep this to the smallest set that explains portfolio fields,
   risk calculations, and paper/live separation.
4. Read Kraken Bot V2 artifacts only from the allowlist. Treat artifacts as
   observations, not commands.
5. Read OpenClaw only for comparable advisory outputs or research notes. Do not
   copy OpenClaw assumptions into Kraken Bot V2 behavior.
6. Summarize:
   - scope and sources,
   - current portfolio/exposure observations,
   - cash/open-order posture if available,
   - risk and safety observations,
   - material risks or inconsistencies,
   - source confidence and artifact freshness,
   - OpenClaw comparison notes,
   - explicit assumptions and verification gaps,
   - safe next steps.
7. Run the validation checklist before final response.

## Output Format

Produce a concise operator review with these sections:

1. **Scope and sources**
   - Repositories and files/artifacts inspected.
   - Whether generated context was present and fresh.
2. **Portfolio posture**
   - Holdings/exposure summary if available.
   - Cash/open-order posture if available.
   - Any missing data clearly labeled.
3. **Risk and safety observations**
   - Existing safety gates observed from source/config/context.
   - No claims about live behavior unless verified from source or current
     artifacts.
4. **Operator-relevant findings**
   - Items that require attention.
   - Items that are informational only.
5. **OpenClaw comparison**
   - Optional advisory/reporting comparison only.
   - No execution authority or behavior changes inferred from OpenClaw.
6. **Assumptions**
   - Explicit assumptions made because data was unavailable or out of scope.
7. **Verification gaps**
   - What was not inspected.
   - What command or artifact would close the gap.
8. **Safe next steps**
   - Read-only or PR-based follow-ups first.
   - Escalate risky operations separately.

## Validation Checklist

Before answering, prove no writes were performed:

- [ ] Read `docs/CURRENT_STATE.md` first when present.
- [ ] Kept inspection within bounded file/artifact limits or got approval to
      expand.
- [ ] Show `git status --short` for Hermes, Kraken Bot V2, and OpenClaw if
      those repos were inspected.
- [ ] Show `git diff --name-only` for Kraken Bot V2 and OpenClaw is empty
      relative to the review work.
- [ ] Confirm no command used redirection, append, file creation, deletion,
      move, install, deploy, service restart, migration, cleanup, state repair,
      or exchange write operation.
- [ ] Confirm no `.env`, launchd, secret, override/promotion mutation, runtime
      state, live bot code, or trading execution path was opened or edited.
- [ ] Confirm no order was placed, cancelled, replaced, or replayed.
- [ ] Listed all inspected sources.
- [ ] Labeled assumptions and verification gaps.
- [ ] Preserved Kraken Bot V2 as the only live execution authority.
- [ ] Confirm OpenClaw was used for comparison only.

## Pitfalls

- Treating Hermes as an executor. Hermes may summarize and advise, but must not
  place trades or mutate live bot behavior.
- Over-reading runtime artifacts. Only inspect artifacts necessary for the
  operator question.
- Trusting generated context over source. Generated state is advisory;
  source/config/runtime artifacts win on conflict.
- Forgetting stale context handling. If CURRENT_STATE or task context is stale,
  stop and name the refresh command.
- Conflating OpenClaw with authority. OpenClaw is legacy advisory/reporting
  context only.
- Hiding uncertainty. Always include assumptions and verification gaps.
- Runtime artifacts can be stale or partially written by another process. Check
  timestamps and source definitions before drawing conclusions.
- Historical orders and trades may be safe to read but unsafe to replay or feed
  into write APIs. Keep them observational.

## Verification

For this skill itself, validate with:

```bash
git status --short
git diff -- skills/portfolio-review/SKILL.md docs/portfolio-review-runbook.md
```

The expected diff is documentation-only. No OpenClaw or Kraken Bot V2 files
should appear in the changed-file list.
