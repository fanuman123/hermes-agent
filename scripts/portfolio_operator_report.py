#!/usr/bin/env python3
"""Hermes-native read-only operator report for Kraken Bot V2 posture."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
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
    "freshness_status",
    "data_age_minutes",
    "health_status",
    "health_reasons",
    "recommended_operator_action",
)


def _artifact_data(review: dict[str, Any], relative: str) -> dict[str, Any]:
    data = review.get("artifacts", {}).get(relative, {}).get("data")
    return data if isinstance(data, dict) else {}


def _count(value: Any, expected_type: type) -> int | None:
    return len(value) if isinstance(value, expected_type) else None


def _is_positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and value > 0


def _parse_exposure(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _parse_snapshot_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _classify_freshness(
    timestamp_value: Any,
    *,
    now_utc: datetime,
    stale_after_minutes: int,
) -> tuple[str, float | None, str | None]:
    if not timestamp_value:
        return "missing_timestamp", None, "missing snapshot timestamp"
    try:
        parsed = _parse_snapshot_timestamp(timestamp_value)
    except (TypeError, ValueError):
        return "invalid_timestamp", None, "invalid snapshot timestamp"
    if parsed is None:
        return "missing_timestamp", None, "missing snapshot timestamp"

    age_minutes = max((now_utc - parsed).total_seconds() / 60.0, 0.0)
    if age_minutes > stale_after_minutes:
        return "stale", round(age_minutes, 2), f"snapshot older than {stale_after_minutes} minutes"
    return "fresh", round(age_minutes, 2), None


def build_operator_report(
    root: Path = DEFAULT_KRAKEN_ROOT,
    *,
    now_utc: datetime | None = None,
    stale_after_minutes: int = 30,
) -> dict[str, Any]:
    """Build the operator report using the validator's read/refusal path."""

    now = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
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
    raw_exposure_pct = portfolio.get("exposure_pct", telegram.get("exposure_pct"))
    exposure_pct = _parse_exposure(raw_exposure_pct)
    entries_allowed = portfolio.get("entries_allowed", telegram.get("entries_allowed"))
    entry_paused = state.get("entry_paused")
    snapshot_ts_utc = portfolio.get("ts_utc") or orders.get("ts_utc")
    freshness_status, data_age_minutes, freshness_reason = _classify_freshness(
        snapshot_ts_utc,
        now_utc=now,
        stale_after_minutes=stale_after_minutes,
    )

    has_artifact_problem = bool(missing_or_unreadable or refused)
    health_reasons: list[str] = []
    if missing_or_unreadable:
        health_reasons.append("required artifact missing or unreadable")
    if refused:
        health_reasons.append("required artifact refused by safety checks")
    if freshness_reason:
        health_reasons.append(freshness_reason)
    if raw_exposure_pct is None or exposure_pct is None:
        health_reasons.append("exposure_pct cannot be parsed")
    if holdings_count is None:
        health_reasons.append("holdings count unavailable")
    if positions_count is None:
        health_reasons.append("positions count unavailable")
    if open_orders_count is None:
        health_reasons.append("open orders count unavailable")
    if entries_allowed is None:
        health_reasons.append("entries_allowed missing")
    if entry_paused is None:
        health_reasons.append("entry_paused missing")
    if not portfolio.get("strategy") and not telegram.get("strategy"):
        health_reasons.append("strategy missing")

    telegram_positions = telegram.get("positions")
    telegram_positions_count = _count(telegram_positions, list)
    if (
        telegram_positions_count is not None
        and positions_count is not None
        and telegram_positions_count != positions_count
    ):
        health_reasons.append("conflicting position counts between state and telegram status")

    has_active_posture = any(
        count is not None and count > 0
        for count in (holdings_count, positions_count, open_orders_count)
    ) or _is_positive_number(exposure_pct)
    has_gate_concern = entries_allowed is False or entry_paused is True

    attention_conditions = (
        has_artifact_problem
        or freshness_status == "invalid_timestamp"
        or raw_exposure_pct is None
        or exposure_pct is None
        or "conflicting position counts between state and telegram status" in health_reasons
    )
    degraded_conditions = (
        freshness_status in {"stale", "missing_timestamp"}
        or has_gate_concern
        or bool(health_reasons)
    )

    if attention_conditions:
        health_status = "ATTENTION_REQUIRED"
    elif degraded_conditions:
        health_status = "DEGRADED"
    else:
        health_status = "HEALTHY"

    if health_status == "ATTENTION_REQUIRED" or has_gate_concern:
        posture = "DEGRADED"
    elif has_active_posture:
        posture = "ACTIVE"
    else:
        posture = "FLAT"

    if health_status == "ATTENTION_REQUIRED" or has_gate_concern:
        action = "pause-review-needed"
    elif health_status == "DEGRADED" or has_active_posture:
        action = "investigate"
    else:
        action = "observe"

    return {
        "strategy": portfolio.get("strategy") or telegram.get("strategy") or "unknown",
        "snapshot_ts_utc": snapshot_ts_utc or "unknown",
        "holdings_count": holdings_count,
        "positions_count": positions_count,
        "open_orders_count": open_orders_count,
        "exposure_pct": exposure_pct,
        "entries_allowed": entries_allowed,
        "entry_paused": entry_paused,
        "posture": posture,
        "freshness_status": freshness_status,
        "data_age_minutes": data_age_minutes,
        "health_status": health_status,
        "health_reasons": health_reasons,
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
    health_reason_lines = [f"- {reason}" for reason in report["health_reasons"]] or ["- none"]
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
        f"freshness_status: {report['freshness_status']}",
        f"data_age_minutes: {report['data_age_minutes']}",
        f"health_status: {report['health_status']}",
        "health_reasons:",
        *health_reason_lines,
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
    parser.add_argument(
        "--stale-after-minutes",
        type=int,
        default=30,
        help="Classify snapshots older than this threshold as stale. Default: 30.",
    )
    args = parser.parse_args()

    report = build_operator_report(
        DEFAULT_KRAKEN_ROOT,
        stale_after_minutes=args.stale_after_minutes,
    )
    if args.json:
        print(format_json_report(report))
    else:
        print(format_text_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
