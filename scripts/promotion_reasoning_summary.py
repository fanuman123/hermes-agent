#!/usr/bin/env python3
"""Hermes-native advisory promotion/override reasoning summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.portfolio_operator_report import DEFAULT_KRAKEN_ROOT, build_operator_report
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from portfolio_operator_report import DEFAULT_KRAKEN_ROOT, build_operator_report


def _reasoning_outcome(operator: dict[str, Any]) -> tuple[str, list[str]]:
    reasons = list(operator["health_reasons"])
    if operator["health_status"] == "HEALTHY":
        reasons.append("portfolio snapshot is healthy enough for human advisory review")
        return "eligible_for_human_review", reasons
    if operator["health_status"] == "DEGRADED":
        reasons.append("portfolio snapshot is degraded; investigate before any separate promotion review")
        return "review_degraded_inputs", reasons
    reasons.append("portfolio snapshot requires attention; do not use for promotion or override decisions")
    return "blocked_pending_human_review", reasons


def build_promotion_reasoning_summary(
    root: Path = DEFAULT_KRAKEN_ROOT,
) -> dict[str, Any]:
    operator = build_operator_report(root)
    outcome, reasons = _reasoning_outcome(operator)
    gate_reasons: list[str] = []
    if operator["entries_allowed"] is False:
        gate_reasons.append("entries_allowed is false")
    if operator["entry_paused"] is True:
        gate_reasons.append("entry_paused is true")
    if operator["artifacts_missing_or_unreadable"]:
        gate_reasons.append("required Kraken Bot V2 snapshot artifact missing or unreadable")
    if operator["artifacts_refused"]:
        gate_reasons.append("required Kraken Bot V2 snapshot artifact refused")

    return {
        "strategy": operator["strategy"],
        "posture": operator["posture"],
        "freshness_status": operator["freshness_status"],
        "health_status": operator["health_status"],
        "recommended_operator_action": operator["recommended_operator_action"],
        "reasoning_outcome": outcome,
        "reasoning_reasons": reasons,
        "gate_reasons": gate_reasons,
        "advisory_only": True,
        "promotion_authority": False,
        "override_authority": False,
        "execution_authority": "Kraken Bot V2",
        "artifacts_read": operator["artifacts_read"],
        "artifacts_missing_or_unreadable": operator["artifacts_missing_or_unreadable"],
        "artifacts_refused": operator["artifacts_refused"],
        "no_write_safety": {
            "read_only": True,
            "writes_reports": False,
            "writes_overrides": False,
            "writes_promotions": False,
            "places_orders": False,
            "mutates_runtime_state": False,
        },
    }


def format_text_summary(summary: dict[str, Any]) -> str:
    reasoning_lines = [f"- {item}" for item in summary["reasoning_reasons"]] or ["- none"]
    gate_lines = [f"- {item}" for item in summary["gate_reasons"]] or ["- none"]
    lines = [
        "Hermes promotion/override reasoning summary",
        f"strategy: {summary['strategy']}",
        f"posture: {summary['posture']}",
        f"freshness_status: {summary['freshness_status']}",
        f"health_status: {summary['health_status']}",
        f"recommended_operator_action: {summary['recommended_operator_action']}",
        f"reasoning_outcome: {summary['reasoning_outcome']}",
        "",
        "Reasoning reasons:",
        *reasoning_lines,
        "",
        "Gate reasons:",
        *gate_lines,
        "",
        "Safety:",
        "- advisory-only and human-review-only",
        "- no promotion execution and no override mutation",
        "- Kraken Bot V2 remains the only execution authority",
    ]
    return "\n".join(lines)


def format_json_summary(summary: dict[str, Any]) -> str:
    return json.dumps(summary, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()
    summary = build_promotion_reasoning_summary()
    print(format_json_summary(summary) if args.json else format_text_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
