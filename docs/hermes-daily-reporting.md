# Hermes Daily Portfolio Reporting

## Purpose

`scripts/daily_portfolio_report.py` generates a markdown daily operator summary
from the same four Kraken Bot V2 snapshot artifacts used by the Hermes
operator report. It is read-only and stdout-first.

This replaces the next basic OpenClaw reporting slice: a daily portfolio
posture summary for operator review.

## Replaced OpenClaw Slice

The daily report covers:

- report date and timestamp,
- portfolio posture,
- freshness and health classification,
- exposure,
- open positions and orders counts,
- entry gate status,
- recommended human action,
- no-write safety footer,
- explicit "not exchange reconciliation" disclaimer.

## Still OpenClaw-Owned

OpenClaw remains legacy/comparison-only for historical trade analysis, richer
advisory research, backtests, strategy promotion reasoning, and migration
planning until separate Hermes-native replacements exist.

## Allowed Inputs

The daily report reuses `portfolio_operator_report.py`, which reads only:

- `/opt/bots/kraken-bot-v2/data/state.json`
- `/opt/bots/kraken-bot-v2/data/portfolio_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/open_orders_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/telegram_status.json`

It does not read logs, OpenClaw, `.env`, launchd, overrides, promotions,
trading execution code, or Kraken Bot V2 runtime state outside those snapshots.

## How to Run

Markdown to stdout:

```bash
python3 scripts/daily_portfolio_report.py
```

JSON to stdout:

```bash
python3 scripts/daily_portfolio_report.py --json
```

Optional file output is allowed only under the Hermes repo `reports/daily/`
directory:

```bash
python3 scripts/daily_portfolio_report.py --output reports/daily/portfolio-2099-01-02.md
```

Paths outside `reports/daily/` are refused.

## Sample Output

```markdown
# Daily Portfolio Report - 2099-01-02

Report timestamp UTC: `2099-01-02T03:14:05Z`

## Portfolio Posture

- Strategy: `SAMPLE_S01`
- Posture: `FLAT`
- Exposure: `0.0`%
- Holdings count: `0`
- Positions count: `0`
- Open orders count: `0`

## Freshness And Health

- Snapshot timestamp UTC: `2099-01-02T03:04:05Z`
- Freshness: `fresh`
- Data age minutes: `10.0`
- Health: `HEALTHY`
- Health reasons:
- none

## Recommended Human Action

`observe`

## Safety

- Read-only Hermes report.
- Kraken Bot V2 remains the only execution authority.
- No orders, no runtime mutation, no OpenClaw access, no overrides/promotions.
- This is not exchange reconciliation.
```

The sample uses fake values and is not live account data.

## Rollback / No-Op Safety

If stdout mode is used, rollback is a no-op: stop running the command. If
`--output` is used, the only generated artifact is a Hermes-local file under
`reports/daily/`; no Kraken Bot V2, OpenClaw, exchange, launchd, override, or
runtime state is modified.
