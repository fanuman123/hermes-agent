# Portfolio Review Output Contract

## Purpose

This contract defines the operator-facing stdout produced by the Hermes
dry-run portfolio review validator. It makes the validator output predictable
enough for an operator or future Hermes skill to summarize, while preserving
the existing safety boundary: Hermes reports; Kraken Bot V2 remains the only
execution authority.

The validator is a reporting aid only. It does not trade, rebalance, change
configuration, write reports, mutate runtime state, inspect OpenClaw, or grant
permission to change live bot behavior.

## Exact Allowed Inputs

The validator may read only these four Kraken Bot V2 snapshot JSON artifacts:

- `/opt/bots/kraken-bot-v2/data/state.json`
- `/opt/bots/kraken-bot-v2/data/portfolio_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/open_orders_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/telegram_status.json`

All other paths are outside the default input contract. In particular, the
validator must refuse `.env`, `strategy_overrides.json`, OpenClaw-linked or
symlinked paths, override/promotion artifacts, broad artifact directories, and
non-allowlisted paths.

## Output Sections

The validator writes a plain-text report to stdout with these sections:

- `Artifacts read`
- `Artifacts missing or unreadable`
- `Portfolio summary`
- `No-write checklist`

The report is intentionally flat. It is suitable for chat, terminal history,
and PR review comments without requiring a JSON consumer.

## Field Notes

The current `Portfolio summary` section is a compact derived view:

- `strategy`: from `portfolio_snapshot.json`, falling back to
  `telegram_status.json`.
- `snapshot_ts_utc`: from `portfolio_snapshot.json`, falling back to
  `open_orders_snapshot.json`.
- `holdings_count`: count of `portfolio_snapshot.json.holdings` when it is a
  list.
- `positions_count`: count of `state.json.positions` when it is a mapping.
- `open_orders_count`: count of `open_orders_snapshot.json.open_orders` when it
  is a list.
- `exposure_pct`: from `portfolio_snapshot.json`, falling back to
  `telegram_status.json`.
- `entries_allowed`: from `portfolio_snapshot.json`, falling back to
  `telegram_status.json`.
- `entry_paused`: from `state.json`.

Missing or malformed artifacts should produce `unknown` summary values rather
than encouraging broader searches.

## Flat / No-Position Example

SAMPLE ONLY. The values below are fake and are not live account data.

```text
Hermes dry-run portfolio review validator
Kraken Bot V2 root: /opt/bots/kraken-bot-v2

Artifacts read:
- data/state.json
- data/portfolio_snapshot.json
- data/open_orders_snapshot.json
- data/telegram_status.json

Artifacts missing or unreadable:
- none

Portfolio summary:
- strategy: SAMPLE_S01
- snapshot_ts_utc: 2099-01-02T03:04:05Z
- holdings_count: 0
- positions_count: 0
- open_orders_count: 0
- exposure_pct: 0.0
- entries_allowed: True
- entry_paused: False

No-write checklist:
- read only fixed four Kraken Bot V2 snapshot JSON artifacts
- did not inspect .env, launchd, secrets, overrides, promotions, or OpenClaw paths
- did not write reports, mutate runtime state, place orders, deploy, restart, or repair state
- refused symlink, OpenClaw-linked, override/promotion, and non-allowlisted paths
```

## Open-Position Example

SAMPLE ONLY. The values below are fake and are not live account data.

```text
Hermes dry-run portfolio review validator
Kraken Bot V2 root: /opt/bots/kraken-bot-v2

Artifacts read:
- data/state.json
- data/portfolio_snapshot.json
- data/open_orders_snapshot.json
- data/telegram_status.json

Artifacts missing or unreadable:
- none

Portfolio summary:
- strategy: SAMPLE_S02
- snapshot_ts_utc: 2099-02-03T04:05:06Z
- holdings_count: 2
- positions_count: 1
- open_orders_count: 1
- exposure_pct: 12.5
- entries_allowed: True
- entry_paused: False

No-write checklist:
- read only fixed four Kraken Bot V2 snapshot JSON artifacts
- did not inspect .env, launchd, secrets, overrides, promotions, or OpenClaw paths
- did not write reports, mutate runtime state, place orders, deploy, restart, or repair state
- refused symlink, OpenClaw-linked, override/promotion, and non-allowlisted paths
```

## Missing Artifact Behavior

If one of the four allowed artifacts is missing, the validator reports it under
`Artifacts missing or unreadable` and continues with whatever safe artifacts are
available. It must not search sibling directories, read logs, inspect OpenClaw,
or infer missing data from non-allowlisted files.

If an allowed artifact path is symlinked, resolves outside the Kraken Bot V2
root, or is otherwise unsafe, the validator reports it as refused rather than
following the path.

## No-Write Guarantees

The validator must:

- read only the four fixed JSON snapshot artifacts,
- print only to stdout,
- avoid report files and temporary output files,
- refuse symlinks and OpenClaw-linked paths,
- refuse `.env`, secrets, launchd, overrides, promotions, and non-allowlisted
  paths,
- avoid trading, rebalancing, deployment, restart, repair, and migration
  behavior.

## Operator Interpretation Guide

- `holdings_count: 0`, `positions_count: 0`, and `open_orders_count: 0` means
  the snapshots present a flat posture; it does not prove the exchange account
  has no activity outside these artifacts.
- A nonzero count is a prompt for read-only human review, not permission to
  close, cancel, rebalance, or mutate state.
- `entries_allowed: True` reports the artifact value only. It is not a
  recommendation to enter trades.
- `entry_paused: False` reports the artifact value only. It is not permission
  to modify pause, override, or promotion logic.
- Missing or `unknown` values should be reported as verification gaps.

## Non-Goals

- No execution migration from Kraken Bot V2 to Hermes.
- No OpenClaw deletion or mutation.
- No live order placement, cancellation, replacement, or replay.
- No override, promotion, risk-gate, execution-config, launchd, or `.env`
  changes.
- No broad artifact discovery, live log review, or filesystem crawling.
- No generated report files.
