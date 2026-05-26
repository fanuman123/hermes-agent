# Hermes-Native Reporting

## Purpose

Hermes-native reporting provides read-only operator reports for Kraken Bot V2
portfolio posture and bounded advisory summaries. It replaces the core OpenClaw
operator/advisory reporting slices that answered:

- what is the current portfolio posture,
- should the operator observe or investigate,
- what does the recent historical trade posture look like,
- how does Hermes posture compare with legacy OpenClaw posture,
- why would a posture be considered healthy, degraded, or blocked for human
  advisory review.

This is a reporting layer only. Kraken Bot V2 remains the only execution
authority. Hermes does not place orders, cancel orders, rebalance, repair
state, mutate config, write overrides, promote policies, or change live bot
behavior.

## Replaced OpenClaw Reporting Slices

Hermes replaces basic posture reporting:

- strategy name from current snapshots,
- snapshot timestamp,
- holdings count,
- positions count,
- open orders count,
- exposure percentage,
- entry gate status,
- compact posture classification,
- recommended operator action.

Hermes also replaces the primary OpenClaw advisory reporting slices with:

- `scripts/historical_trade_summary.py` for bounded trade/fill summaries,
- `scripts/advisory_comparison_report.py` for Hermes-vs-legacy OpenClaw
  posture comparison,
- `scripts/promotion_reasoning_summary.py` for advisory-only
  promotion/override reasoning.

The portfolio operator report remains suitable for Telegram-sized operator
status updates. The advisory commands are terminal/stdout reporting tools and
do not add Telegram-specific behavior.

## Still OpenClaw-Owned

OpenClaw remains legacy/comparison-only for archived context and richer
historical research that is not yet represented by bounded Hermes scripts. The
Hermes commands do not replace:

- backtest reports,
- OpenClaw-specific historical report formats,
- migration planning,
- scheduler ownership,
- strategy promotion execution,
- override mutation.

## Allowed Inputs

The command reuses the same Hermes-side safety path as the dry-run validator
and reads only:

- `/opt/bots/kraken-bot-v2/data/state.json`
- `/opt/bots/kraken-bot-v2/data/portfolio_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/open_orders_snapshot.json`
- `/opt/bots/kraken-bot-v2/data/telegram_status.json`

It refuses `.env`, `strategy_overrides.json`, OpenClaw-linked or symlinked
paths, override/promotion artifacts, broad artifact directories, and
non-allowlisted paths.

## How to Run

From the Hermes repo:

```bash
python3 scripts/portfolio_operator_report.py
```

The default freshness threshold is 30 minutes. To change it:

```bash
python3 scripts/portfolio_operator_report.py --stale-after-minutes 45
```

For machine-readable output:

```bash
python3 scripts/portfolio_operator_report.py --json
```

For a markdown daily operator summary, use:

```bash
python3 scripts/daily_portfolio_report.py
```

For migrated advisory summaries, use:

```bash
python3 scripts/historical_trade_summary.py
python3 scripts/advisory_comparison_report.py
python3 scripts/promotion_reasoning_summary.py
```

See `docs/hermes-advisory-migration.md` for the full migration contract.

## Expected Text Output

```text
Hermes Kraken Bot V2 operator report
strategy: SAMPLE_S01
snapshot_ts_utc: 2099-01-02T03:04:05Z
holdings_count: 0
positions_count: 0
open_orders_count: 0
exposure_pct: 0.0
entries_allowed: True
entry_paused: False
posture: FLAT
freshness_status: fresh
data_age_minutes: 10.0
health_status: HEALTHY
health_reasons:
- none
recommended_operator_action: observe
safety: read-only Hermes report; Kraken Bot V2 remains execution authority.
safety: no writes, no orders, no OpenClaw, no overrides/promotions.
```

The sample above is fake operator output, not live account data.

## Posture and Action

- `FLAT`: no holdings, positions, open orders, or exposure are visible in the
  four snapshots. Recommended action: `observe`.
- `ACTIVE`: holdings, positions, open orders, or positive exposure are visible.
  Recommended action: `investigate`.
- `DEGRADED`: a required artifact is missing/refused/unreadable, or entry gate
  values suggest pause review is needed. Recommended action:
  `investigate` or `pause-review-needed`.

These actions are operator guidance only. They are not permission to place,
cancel, replay, rebalance, pause, unpause, or modify trading behavior.

## Freshness and Health

Freshness is based on `snapshot_ts_utc`, derived from
`portfolio_snapshot.json.ts_utc` with a fallback to
`open_orders_snapshot.json.ts_utc`.

- `fresh`: the snapshot age is within the configured stale threshold.
- `stale`: the snapshot is older than the configured stale threshold.
- `missing_timestamp`: no usable timestamp is present.
- `invalid_timestamp`: the timestamp cannot be parsed.

Health is a conservative operator-readiness classification:

- `HEALTHY`: all four artifacts are readable, timestamp is fresh, exposure is
  parsed, and critical posture fields are present.
- `DEGRADED`: metadata is incomplete or stale, but the report remains safe for
  read-only operator interpretation.
- `ATTENTION_REQUIRED`: a required artifact is missing/unreadable/refused, the
  timestamp is invalid, exposure cannot be parsed, or position counts conflict.

Recommended actions are bounded to human review:

- `observe`: healthy flat posture.
- `investigate`: degraded posture or active posture.
- `pause-review-needed`: attention-required posture or entry-gate concern. This
  means human review only; it does not pause the bot or modify any live setting.

## Read-Only Safety

The command writes only to stdout. It creates no report file and uses no
temporary output path. It does not inspect live logs, OpenClaw, `.env`,
launchd, overrides, promotions, trading execution code, or bot runtime state
outside the four allowlisted snapshot artifacts.

## Rollback / No-Op Safety

Rollback is a no-op operationally: stop running the command. There is no
runtime state, config, service, or exchange-side artifact to undo because the
command is read-only and stdout-only.

For the daily report, any optional file output is limited to
`reports/daily/` inside the Hermes repo. Advisory commands write only to
stdout.
