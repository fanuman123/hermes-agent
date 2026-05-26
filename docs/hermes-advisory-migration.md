# Hermes Advisory Migration

## Purpose

This document marks the bounded Hermes-native replacements for the remaining
core OpenClaw operator/advisory reporting slices. The migration is read-only and
human-review-only. Kraken Bot V2 remains the only execution authority.

Hermes now owns basic portfolio posture reporting plus bounded advisory
summaries for historical trades, legacy comparison, and promotion/override
reasoning. These commands do not place orders, cancel orders, write overrides,
promote strategies, reconcile the exchange account, mutate OpenClaw, or change
Kraken Bot V2 runtime state.

## Migrated To Hermes

- Basic portfolio posture:
  `scripts/portfolio_operator_report.py`
- Daily portfolio operator summary:
  `scripts/daily_portfolio_report.py`
- Historical trade summary:
  `scripts/historical_trade_summary.py`
- Advisory comparison summary:
  `scripts/advisory_comparison_report.py`
- Promotion/override reasoning summary:
  `scripts/promotion_reasoning_summary.py`

## Historical Trade Summary

Run:

```bash
python3 scripts/historical_trade_summary.py
```

The command reads only bounded Kraken Bot V2 trade/fill artifacts:

- `/opt/bots/kraken-bot-v2/data/fills.json`
- `/opt/bots/kraken-bot-v2/data/fills.csv`
- `/opt/bots/kraken-bot-v2/data/trades.json`
- `/opt/bots/kraken-bot-v2/data/trades.csv`

It reports row counts, realized PnL availability, win/loss counts, symbols, and
a conservative performance trend. Missing artifacts are reported as missing. It
does not search for alternate files.

## Advisory Comparison Summary

Run:

```bash
python3 scripts/advisory_comparison_report.py
```

The command compares Hermes portfolio posture against legacy OpenClaw posture
when allowlisted OpenClaw report artifacts exist:

- `/opt/bots/openclaw/data/reports/latest/operator_context.json`
- `/opt/bots/openclaw/data/reports/latest/facts.json`
- `/opt/bots/openclaw/data/reports/latest/operator_summary.md`

The result is comparison-only. It has no promotion authority and no override
authority.

## Promotion / Override Reasoning Summary

Run:

```bash
python3 scripts/promotion_reasoning_summary.py
```

The command reuses the strict four-snapshot portfolio validator path and
explains why the current posture is healthy, degraded, or attention-required for
human advisory review. It does not read or write `strategy_overrides.json`, does
not inspect promotion artifacts, and does not mutate any gate.

## Explicit Non-Goals

- No execution migration from Kraken Bot V2 to Hermes.
- No exchange reconciliation guarantee.
- No OpenClaw code deletion.
- No scheduler disablement.
- No Telegram-specific work.
- No live order placement, cancellation, repair, replay, or rebalance.
- No override write, promotion write, risk-gate mutation, `.env`, launchd, or
  runtime-state change.
- No broad artifact discovery, live log review, or filesystem crawling.

## Migration Completion Sections

### Migrated To Hermes

Hermes now owns the primary read-only reporting/advisory surfaces:

- portfolio validator,
- portfolio operator report,
- freshness and health classification,
- daily portfolio report,
- historical trade summary,
- advisory comparison summary,
- promotion/override reasoning summary.

### Legacy / OpenClaw-Only

OpenClaw remains legacy/comparison-only for:

- historical archived report review,
- advisory research notebooks and backtests,
- older OpenClaw-specific report formats,
- historical context needed to explain previous operator decisions.

OpenClaw outputs must not drive live execution.

### Intentionally Not Migrated

These remain outside Hermes reporting authority:

- live execution,
- exchange reconciliation,
- strategy promotion execution,
- override mutation,
- scheduler ownership,
- Kraken Bot V2 runtime state repair,
- launchd or service management.

## Safety Footer

All migrated commands are stdout-first, read-only, and bounded by explicit
artifact allowlists. Optional daily report file output is restricted to the
Hermes repo under `reports/daily/`. Kraken Bot V2 remains the only execution
authority.
