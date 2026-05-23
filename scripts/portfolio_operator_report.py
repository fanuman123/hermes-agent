#!/usr/bin/env python3
"""Hermes-native read-only operator report for Kraken Bot V2 posture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.portfolio_review_validator import DEFAULT_KRAKEN_ROOT, build_review
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from portfolio_review_validator import DEFAULT_KRAKEN_ROOT, build_review


REPORT_FIELDS = (
    "strategy",
    "snapshot_ts_utc",
    "holdings_count",
    "positions_count",
    "open_orders_count",
    "exposure_pct",
    "entries_allowed",
    "entry_paused",
    "posture",
    "recommended_operator_action",
)


def _artifact_data(review: dict[str, Any], relative: str) -> dict[str, Any]:
    data = review.get("artifacts", {}).get(relative, {}).get("data")
    return data if isinstance(data, dict) else {}


def _count(value: Any, expected_type: type) -> int | None:
    return len(value) if isinstance(value, expected_type) else None


def _is_positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and value > 0


def build_operator_report(root: Path = DEFAULT_KRAKEN_ROOT) -> dict[str, Any]:
    """Build the operator report using the validator's read/refusal path."""

    review = build_review(root)
    portfolio = _artifact_data(review, "data/portfolio_snapshot.json")
    orders = _artifact_data(review, "data/open_orders_snapshot.json")
    telegram = _artifact_data(review, "data/telegram_status.json")
    state = _artifact_data(review, "data/state.json")

    artifacts = review["artifacts"]
    missing_or_unreadable = {
        rel: item["status"]
        for rel, item in artifacts.items()
        if item["status"] != "read"
    }
    refused = dict(review["refused"])

    holdings_count = _count(portfolio.get("holdings"), list)
    positions_count = _count(state.get("positions"), dict)
    open_orders_count = _count(orders.get("open_orders"), list)
    exposure_pct = portfolio.get("exposure_pct", telegram.get("exposure_pct"))
    entries_allowed = portfolio.get("entries_allowed", telegram.get("entries_allowed"))
    entry_paused = state.get("entry_paused")

    has_artifact_problem = bool(missing_or_unreadable or refused)
    has_active_posture = any(
        count is not None and count > 0
        for count in (holdings_count, positions_count, open_orders_count)
    ) or _is_positive_number(exposure_pct)
    has_gate_concern = entries_allowed is False or entry_paused is True

    if has_artifact_problem or has_gate_concern:
        posture = "DEGRADED"
    elif has_active_posture:
        posture = "ACTIVE"
    else:
        posture = "FLAT"

    if has_gate_concern:
        action = "pause-review-needed"
    elif has_artifact_problem or has_active_posture:
        action = "investigate"
    else:
        action = "observe"

    return {
        "strategy": portfolio.get("strategy") or telegram.get("strategy") or "unknown",
        "snapshot_ts_utc": portfolio.get("ts_utc") or orders.get("ts_utc") or "unknown",
        "holdings_count": holdings_count,
        "positions_count": positions_count,
        "open_orders_count": open_orders_count,
        "exposure_pct": exposure_pct,
        "entries_allowed": entries_allowed,
        "entry_paused": entry_paused,
        "posture": posture,
        "recommended_operator_action": action,
        "artifacts_read": [
            rel for rel, item in artifacts.items() if item["status"] == "read"
        ],
        "artifacts_missing_or_unreadable": missing_or_unreadable,
        "artifacts_refused": refused,
        "no_write_safety": {
            "read_only_allowlist": True,
            "writes_reports": False,
            "mutates_runtime_state": False,
            "places_orders": False,
            "touches_openclaw": False,
            "touches_overrides_or_promotions": False,
        },
    }


def format_text_report(report: dict[str, Any]) -> str:
    lines = [
        "Hermes Kraken Bot V2 operator report",
        f"strategy: {report['strategy']}",
        f"snapshot_ts_utc: {report['snapshot_ts_utc']}",
        f"holdings_count: {report['holdings_count']}",
        f"positions_count: {report['positions_count']}",
        f"open_orders_count: {report['open_orders_count']}",
        f"exposure_pct: {report['exposure_pct']}",
        f"entries_allowed: {report['entries_allowed']}",
        f"entry_paused: {report['entry_paused']}",
        f"posture: {report['posture']}",
        f"recommended_operator_action: {report['recommended_operator_action']}",
    ]

    if report["artifacts_missing_or_unreadable"] or report["artifacts_refused"]:
        lines.append("artifact_status: degraded")
        for rel, status in report["artifacts_missing_or_unreadable"].items():
            lines.append(f"- {rel}: {status}")
        for rel, reason in report["artifacts_refused"].items():
            lines.append(f"- {rel}: refused: {reason}")

    lines.extend(
        [
            "safety: read-only Hermes report; Kraken Bot V2 remains execution authority.",
            "safety: no writes, no orders, no OpenClaw, no overrides/promotions.",
        ]
    )
    return "\n".join(lines)


def format_json_report(report: dict[str, Any]) -> str:
    fields = (
        *REPORT_FIELDS,
        "artifacts_read",
        "artifacts_missing_or_unreadable",
        "artifacts_refused",
        "no_write_safety",
    )
    return json.dumps({field: report[field] for field in fields}, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    report = build_operator_report(DEFAULT_KRAKEN_ROOT)
    if args.json:
        print(format_json_report(report))
    else:
        print(format_text_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
