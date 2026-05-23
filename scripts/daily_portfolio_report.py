#!/usr/bin/env python3
"""Hermes-native daily portfolio report for Kraken Bot V2 snapshots."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.portfolio_operator_report import (
        DEFAULT_KRAKEN_ROOT,
        build_operator_report,
        format_json_report,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from portfolio_operator_report import DEFAULT_KRAKEN_ROOT, build_operator_report, format_json_report


REPO_ROOT = Path(__file__).resolve().parent.parent
DAILY_REPORT_DIR = Path("reports/daily")


class OutputPathRefused(ValueError):
    """Raised when a daily report output path is outside the Hermes reports dir."""


def _has_symlink_component(path: Path, stop_at: Path) -> bool:
    current = path
    while current != stop_at and current != current.parent:
        if current.exists() and current.is_symlink():
            return True
        current = current.parent
    return False


def resolve_output_path(output: Path | str, *, repo_root: Path = REPO_ROOT) -> Path:
    requested = Path(output)
    candidate = requested if requested.is_absolute() else repo_root / requested
    allowed_dir = (repo_root / DAILY_REPORT_DIR).resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)

    try:
        resolved_candidate.relative_to(allowed_dir)
    except ValueError as exc:
        raise OutputPathRefused("daily reports may only be written under reports/daily/") from exc

    if _has_symlink_component(candidate, repo_root):
        raise OutputPathRefused("daily report output path must not traverse symlinks")

    return candidate


def build_daily_report(
    root: Path = DEFAULT_KRAKEN_ROOT,
    *,
    now_utc: datetime | None = None,
    stale_after_minutes: int = 30,
) -> dict[str, Any]:
    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    operator = build_operator_report(
        root,
        now_utc=now,
        stale_after_minutes=stale_after_minutes,
    )
    return {
        "report_date": now.date().isoformat(),
        "report_ts_utc": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "operator_report": operator,
        "not_exchange_reconciliation": True,
        "safety": {
            "read_only": True,
            "writes_only_optional_hermes_report": True,
            "kraken_bot_v2_execution_authority": True,
            "touches_openclaw": False,
            "touches_runtime_state": False,
            "places_orders": False,
        },
    }


def _format_health_reasons(report: dict[str, Any]) -> list[str]:
    reasons = report["operator_report"]["health_reasons"]
    return [f"- {reason}" for reason in reasons] or ["- none"]


def format_markdown_report(report: dict[str, Any]) -> str:
    operator = report["operator_report"]
    lines = [
        f"# Daily Portfolio Report - {report['report_date']}",
        "",
        f"Report timestamp UTC: `{report['report_ts_utc']}`",
        "",
        "## Portfolio Posture",
        "",
        f"- Strategy: `{operator['strategy']}`",
        f"- Posture: `{operator['posture']}`",
        f"- Exposure: `{operator['exposure_pct']}`%",
        f"- Holdings count: `{operator['holdings_count']}`",
        f"- Positions count: `{operator['positions_count']}`",
        f"- Open orders count: `{operator['open_orders_count']}`",
        "",
        "## Freshness And Health",
        "",
        f"- Snapshot timestamp UTC: `{operator['snapshot_ts_utc']}`",
        f"- Freshness: `{operator['freshness_status']}`",
        f"- Data age minutes: `{operator['data_age_minutes']}`",
        f"- Health: `{operator['health_status']}`",
        "- Health reasons:",
        *_format_health_reasons(report),
        "",
        "## Open Positions And Orders",
        "",
        f"- Open positions visible in snapshots: `{operator['positions_count']}`",
        f"- Open orders visible in snapshots: `{operator['open_orders_count']}`",
        "",
        "## Entry Gate",
        "",
        f"- Entries allowed: `{operator['entries_allowed']}`",
        f"- Entry paused: `{operator['entry_paused']}`",
        "",
        "## Recommended Human Action",
        "",
        f"`{operator['recommended_operator_action']}`",
        "",
        "## Safety",
        "",
        "- Read-only Hermes report.",
        "- Kraken Bot V2 remains the only execution authority.",
        "- No orders, no runtime mutation, no OpenClaw access, no overrides/promotions.",
        "- This is not exchange reconciliation.",
    ]
    return "\n".join(lines)


def format_json_daily_report(report: dict[str, Any]) -> str:
    payload = {
        "report_date": report["report_date"],
        "report_ts_utc": report["report_ts_utc"],
        "not_exchange_reconciliation": report["not_exchange_reconciliation"],
        "operator_report": json.loads(format_json_report(report["operator_report"])),
        "safety": report["safety"],
    }
    return json.dumps(payload, sort_keys=True)


def write_report(content: str, output: Path | str, *, repo_root: Path = REPO_ROOT) -> Path:
    destination = resolve_output_path(output, repo_root=repo_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--stale-after-minutes",
        type=int,
        default=30,
        help="Classify snapshots older than this threshold as stale. Default: 30.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output path under the Hermes repo reports/daily/ directory.",
    )
    args = parser.parse_args()

    report = build_daily_report(stale_after_minutes=args.stale_after_minutes)
    rendered = format_json_daily_report(report) if args.json else format_markdown_report(report)
    if args.output:
        write_report(rendered, args.output)
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
