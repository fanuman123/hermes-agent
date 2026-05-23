#!/usr/bin/env python3
"""Hermes-native read-only advisory comparison report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.portfolio_operator_report import DEFAULT_KRAKEN_ROOT, build_operator_report
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from portfolio_operator_report import DEFAULT_KRAKEN_ROOT, build_operator_report


DEFAULT_OPENCLAW_ROOT = Path("/opt/bots/openclaw")
DEFAULT_OPENCLAW_ARTIFACTS = (
    Path("data/reports/latest/operator_context.json"),
    Path("data/reports/latest/facts.json"),
    Path("data/reports/latest/operator_summary.md"),
)
REFUSED_TOKENS = (
    ".env",
    "launchd",
    "override",
    "promotion",
    "strategy_overrides.json",
)


class OpenClawArtifactRefused(ValueError):
    """Raised when a legacy comparison artifact is outside the allowlist."""


def _has_symlink_component(path: Path, stop_at: Path) -> bool:
    current = path
    while current != stop_at and current != current.parent:
        if current.exists() and current.is_symlink():
            return True
        current = current.parent
    return False


def validate_openclaw_artifact_path(root: Path, requested: Path | str) -> Path:
    requested_path = Path(requested)
    if requested_path.is_absolute():
        try:
            relative = requested_path.relative_to(root)
        except ValueError as exc:
            raise OpenClawArtifactRefused(f"outside OpenClaw root: {requested_path}") from exc
    else:
        relative = requested_path

    normalized = Path(*relative.parts)
    normalized_text = normalized.as_posix().lower()
    if normalized not in DEFAULT_OPENCLAW_ARTIFACTS:
        raise OpenClawArtifactRefused(f"non-allowlisted OpenClaw artifact: {normalized.as_posix()}")
    if any(token in normalized_text for token in REFUSED_TOKENS):
        raise OpenClawArtifactRefused(f"refused sensitive OpenClaw artifact: {normalized.as_posix()}")

    candidate = root / normalized
    if _has_symlink_component(candidate, root):
        raise OpenClawArtifactRefused(f"refused symlink OpenClaw artifact: {normalized.as_posix()}")

    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise OpenClawArtifactRefused(f"OpenClaw artifact resolves outside root: {normalized.as_posix()}") from exc

    return candidate


def _load_artifact(path: Path) -> tuple[Any | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.suffix.lower() == ".json":
        try:
            return json.loads(path.read_text(encoding="utf-8")), None
        except json.JSONDecodeError as exc:
            return None, f"invalid json: {exc}"
    return path.read_text(encoding="utf-8"), None


def _legacy_value(payload: Any, *keys: str) -> Any:
    if not isinstance(payload, dict):
        return None
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _derive_legacy_posture(artifacts: dict[str, dict[str, Any]]) -> str:
    facts = artifacts.get("data/reports/latest/facts.json", {}).get("data")
    operator = artifacts.get("data/reports/latest/operator_context.json", {}).get("data")

    posture = _legacy_value(facts, "posture")
    if isinstance(posture, dict):
        live_flat = posture.get("live_flat")
        open_positions = posture.get("open_positions")
        if live_flat is True:
            return "FLAT"
        if isinstance(open_positions, int) and open_positions > 0:
            return "ACTIVE"

    freshness = _legacy_value(operator, "paper_freshness_status")
    dominant_blocker = _legacy_value(operator, "dominant_blocker")
    if freshness or dominant_blocker:
        return "ADVISORY_AVAILABLE"
    return "UNKNOWN"


def build_advisory_comparison_report(
    kraken_root: Path = DEFAULT_KRAKEN_ROOT,
    openclaw_root: Path = DEFAULT_OPENCLAW_ROOT,
    *,
    openclaw_artifacts: tuple[Path, ...] = DEFAULT_OPENCLAW_ARTIFACTS,
) -> dict[str, Any]:
    hermes = build_operator_report(kraken_root)
    legacy_artifacts: dict[str, dict[str, Any]] = {}
    legacy_refused: dict[str, str] = {}

    for relative in openclaw_artifacts:
        rel_text = Path(relative).as_posix()
        try:
            path = validate_openclaw_artifact_path(openclaw_root, relative)
        except OpenClawArtifactRefused as exc:
            legacy_refused[rel_text] = str(exc)
            continue

        data, error = _load_artifact(path)
        legacy_artifacts[rel_text] = {
            "path": str(path),
            "status": "read" if error is None else error,
            "data": data,
        }

    legacy_missing_or_unreadable = {
        rel: item["status"]
        for rel, item in legacy_artifacts.items()
        if item["status"] != "read"
    }
    legacy_read = [
        rel for rel, item in legacy_artifacts.items() if item["status"] == "read"
    ]
    legacy_posture = _derive_legacy_posture(legacy_artifacts)
    if not legacy_read and legacy_missing_or_unreadable:
        legacy_posture = "LEGACY_MISSING"
    if legacy_refused:
        legacy_posture = "LEGACY_REFUSED"

    posture_match = (
        legacy_posture == hermes["posture"]
        if legacy_posture in {"FLAT", "ACTIVE", "DEGRADED"}
        else None
    )

    return {
        "hermes_posture": hermes["posture"],
        "hermes_health_status": hermes["health_status"],
        "hermes_recommended_operator_action": hermes["recommended_operator_action"],
        "legacy_openclaw_posture": legacy_posture,
        "posture_match": posture_match,
        "comparison_summary": (
            "Hermes and OpenClaw posture agree"
            if posture_match is True
            else "Hermes/OpenClaw posture differs or legacy posture is unavailable"
        ),
        "hermes_artifacts_read": hermes["artifacts_read"],
        "legacy_artifacts_read": legacy_read,
        "legacy_artifacts_missing_or_unreadable": legacy_missing_or_unreadable,
        "legacy_artifacts_refused": legacy_refused,
        "no_write_safety": {
            "read_only": True,
            "comparison_only": True,
            "writes_reports": False,
            "places_orders": False,
            "mutates_openclaw": False,
            "touches_overrides_or_promotions": False,
        },
    }


def format_text_report(report: dict[str, Any]) -> str:
    legacy_read = [f"- {item}" for item in report["legacy_artifacts_read"]] or ["- none"]
    legacy_missing = [
        f"- {item}: {status}"
        for item, status in report["legacy_artifacts_missing_or_unreadable"].items()
    ] or ["- none"]
    legacy_refused = [
        f"- {item}: refused: {reason}"
        for item, reason in report["legacy_artifacts_refused"].items()
    ] or ["- none"]
    lines = [
        "Hermes advisory comparison report",
        f"hermes_posture: {report['hermes_posture']}",
        f"hermes_health_status: {report['hermes_health_status']}",
        f"legacy_openclaw_posture: {report['legacy_openclaw_posture']}",
        f"posture_match: {report['posture_match']}",
        f"recommended_operator_action: {report['hermes_recommended_operator_action']}",
        f"comparison_summary: {report['comparison_summary']}",
        "",
        "Legacy OpenClaw artifacts read:",
        *legacy_read,
        "",
        "Legacy OpenClaw artifacts missing or unreadable:",
        *legacy_missing,
        "",
        "Legacy OpenClaw artifacts refused:",
        *legacy_refused,
        "",
        "Safety:",
        "- comparison-only, human-review-only",
        "- no promotion authority, no override writes, no exchange writes",
        "- Kraken Bot V2 remains execution authority",
    ]
    return "\n".join(lines)


def format_json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()
    report = build_advisory_comparison_report()
    print(format_json_report(report) if args.json else format_text_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
