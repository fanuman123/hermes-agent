# Portfolio Review Runbook

This runbook defines the read-only process for Hermes-native portfolio reviews.
It is intentionally a checklist, not an automation that mutates trading systems.

## Scope

- Hermes hosts the runner/checklist.
- Kraken Bot V2 is the execution source of truth and may be inspected only with
  read-only commands and allowlisted artifacts.
- OpenClaw is comparison-only advisory context.
- No review step may modify OpenClaw, Kraken Bot V2, `.env`, launchd, trading
  execution code, override logic, promotion logic, or safety gates.

## Read-Only Operating Rules

Allowed:

- `git status --short`, `git diff --name-only`, `git log`, `git show`.
- Specific file reads from source files needed to interpret portfolio artifacts.
- Narrow file listings for known directories.
- Timestamp, checksum, and line-display commands that do not write.
- Tests or validators only when they do not write to OpenClaw or Kraken Bot V2.

Forbidden:

- File edits, patches, formatters, migrations, lockfile updates, installs,
  service restarts, deploys, schedulers, launchd changes, or cleanup commands.
- Shell redirection or append operators for trading repo paths.
- Exchange write operations, order submission/cancellation, rebalance commands,
  or state repair commands.
- Reading secrets such as `.env`, keys, credential stores, tokens, or wallet
  material.

## Kraken Bot V2 Artifact Allowlist

Read only these runtime artifact locations, and only as narrowly as needed:

- `logs/`
- `reports/`
- `artifacts/`
- `runs/`
- `data/`
- `state/portfolio*`
- `state/positions*`
- `state/balances*`
- `state/exposure*`
- `state/risk*`
- `state/paper*`
- `state/live*`
- `state/orders*` for historical observation only.
- `state/trades*` for historical observation only.
- `snapshots/`
- `metrics/`
- `backtests/`
- `paper/`
- `live/` for read-only observation only.

Do not read or write secrets, launchd files, deployment files, override state,
promotion state, execution control files, safety-gate state, or exchange-write
configuration unless the user explicitly asks for a read-only source review and
the file is necessary to interpret the portfolio.

## Runner Checklist

1. State the requested review scope and repositories.
2. Capture clean-room baselines:
   - `git -C <hermes> status --short`
   - `git -C <kraken-bot-v2> status --short`
   - `git -C <openclaw> status --short`
3. Identify the smallest set of source files required to understand artifact
   schemas, paper/live separation, and risk calculations.
4. Read Kraken Bot V2 artifacts only from the allowlist.
5. Read OpenClaw advisory outputs only for comparison. Do not propose OpenClaw
   behavior as an execution change.
6. Produce the review in the chat response:
   - portfolio and exposure observations,
   - risk flags,
   - freshness and source confidence,
   - paper/live separation notes,
   - OpenClaw comparison-only notes,
   - unknowns and follow-ups.
7. Run the no-write validation checklist.

## No-Write Validation Checklist

Complete this before the final response:

- `git -C <kraken-bot-v2> diff --name-only` returns no files changed by the
  review.
- `git -C <openclaw> diff --name-only` returns no files changed by the review.
- Hermes changes, if any, are limited to this runbook and
  `skills/portfolio-review/SKILL.md`.
- No command used write redirection, append, deletion, move, install, deploy,
  migration, restart, exchange write, or state repair behavior.
- No `.env`, launchd, secret, trading execution, override, promotion, or
  safety-gate path was edited.
- OpenClaw was comparison-only.

## Output Template

Use this structure for the final portfolio review:

```text
Portfolio observations:
- ...

Risk flags:
- ...

Freshness and confidence:
- ...

OpenClaw comparison:
- ...

No-write validation:
- Kraken Bot V2 changed files: none
- OpenClaw changed files: none
- Forbidden paths touched: none

Risks and unknowns:
- ...
```
