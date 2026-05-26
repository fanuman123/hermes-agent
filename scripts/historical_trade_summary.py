#!/usr/bin/env python3
"""Hermes-native read-only historical trade summary."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


DEFAULT_KRAKEN_ROOT = Path("/opt/bots/kraken-bot-v2")
DEFAULT_TRADE_ARTIFACTS = (
    Path("data/fills.json"),
    Path("data/fills.csv"),
    Path("data/trades.json"),
    Path("data/trades.csv"),
)
REFUSED_TOKENS = (
    ".env",
    "launchd",
    "openclaw",
    "override",
    "promotion",
    "strategy_overrides.json",
)


class TradeArtifactRefused(ValueError):
    """Raised when a trade artifact path falls outside the read allowlist."""


def _has_symlink_component(path: Path, stop_at: Path) -> bool:
    current = path
    while current != stop_at and current != current.parent:
        if current.exists() and current.is_symlink():
            return True
        current = current.parent
    return False


def validate_trade_artifact_path(root: Path, requested: Path | str) -> Path:
    requested_path = Path(requested)
    if requested_path.is_absolute():
        try:
            relative = requested_path.relative_to(root)
        except ValueError as exc:
            raise TradeArtifactRefused(f"outside Kraken Bot V2 root: {requested_path}") from exc
    else:
        relative = requested_path

    normalized = Path(*relative.parts)
    normalized_text = normalized.as_posix().lower()
    if normalized not in DEFAULT_TRADE_ARTIFACTS:
        raise TradeArtifactRefused(f"non-allowlisted trade artifact: {normalized.as_posix()}")
    if any(token in normalized_text for token in REFUSED_TOKENS):
        raise TradeArtifactRefused(f"refused sensitive trade artifact: {normalized.as_posix()}")

    candidate = root / normalized
    if _has_symlink_component(candidate, root):
        raise TradeArtifactRefused(f"refused symlink trade artifact: {normalized.as_posix()}")

    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise TradeArtifactRefused(f"trade artifact resolves outside root: {normalized.as_posix()}") from exc

    return candidate


def _load_json_trades(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], f"invalid json: {exc}"

    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("fills") or payload.get("trades") or payload.get("rows") or []
    else:
        return [], "json root is not a list or object"

    if not isinstance(rows, list):
        return [], "trade rows are not a list"
    return [row for row in rows if isinstance(row, dict)], None


def _load_csv_trades(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle)), None
    except csv.Error as exc:
        return [], f"invalid csv: {exc}"


def _load_trade_artifact(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    if not path.exists():
        return [], "missing"
    if path.suffix.lower() == ".json":
        return _load_json_trades(path)
    if path.suffix.lower() == ".csv":
        return _load_csv_trades(path)
    return [], "unsupported file type"


def _parse_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _trade_pnl(row: dict[str, Any]) -> float | None:
    for key in ("realized_pnl", "realised_pnl", "pnl", "profit", "profit_usd"):
        parsed = _parse_float(row.get(key))
        if parsed is not None:
            return parsed
    return None


def _row_symbol(row: dict[str, Any]) -> str | None:
    for key in ("symbol", "pair", "market"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_historical_trade_summary(
    root: Path = DEFAULT_KRAKEN_ROOT,
    *,
    artifacts: tuple[Path, ...] = DEFAULT_TRADE_ARTIFACTS,
) -> dict[str, Any]:
    artifacts_read: list[str] = []
    artifacts_missing_or_unreadable: dict[str, str] = {}
    artifacts_refused: dict[str, str] = {}
    rows: list[dict[str, Any]] = []

    for relative in artifacts:
        rel_text = Path(relative).as_posix()
        try:
            path = validate_trade_artifact_path(root, relative)
        except TradeArtifactRefused as exc:
            artifacts_refused[rel_text] = str(exc)
            continue

        loaded, error = _load_trade_artifact(path)
        if error:
            artifacts_missing_or_unreadable[rel_text] = error
            continue
        artifacts_read.append(rel_text)
        rows.extend(loaded)

    pnl_values = [pnl for pnl in (_trade_pnl(row) for row in rows) if pnl is not None]
    wins = sum(1 for pnl in pnl_values if pnl > 0)
    losses = sum(1 for pnl in pnl_values if pnl < 0)
    flat = sum(1 for pnl in pnl_values if pnl == 0)
    symbols = sorted({symbol for symbol in (_row_symbol(row) for row in rows) if symbol})
    net_pnl = round(sum(pnl_values), 8) if pnl_values else None
    avg_pnl = round(sum(pnl_values) / len(pnl_values), 8) if pnl_values else None

    if not rows:
        trend = "no_trade_rows"
    elif not pnl_values:
        trend = "pnl_unavailable"
    elif net_pnl and net_pnl > 0:
        trend = "positive_realized_trend"
    elif net_pnl and net_pnl < 0:
        trend = "negative_realized_trend"
    else:
        trend = "flat_realized_trend"

    return {
        "artifacts_read": artifacts_read,
        "artifacts_missing_or_unreadable": artifacts_missing_or_unreadable,
        "artifacts_refused": artifacts_refused,
        "trade_rows_count": len(rows),
        "pnl_rows_count": len(pnl_values),
        "wins_count": wins,
        "losses_count": losses,
        "flat_count": flat,
        "net_realized_pnl": net_pnl,
        "avg_realized_pnl": avg_pnl,
        "symbols": symbols,
        "performance_trend": trend,
        "operator_note": "historical summary only; not exchange reconciliation",
        "no_write_safety": {
            "read_only": True,
            "writes_reports": False,
            "places_orders": False,
            "mutates_runtime_state": False,
            "touches_overrides_or_promotions": False,
        },
    }


def format_text_summary(summary: dict[str, Any]) -> str:
    read_lines = [f"- {item}" for item in summary["artifacts_read"]] or ["- none"]
    missing_lines = [
        f"- {item}: {status}"
        for item, status in summary["artifacts_missing_or_unreadable"].items()
    ] or ["- none"]
    refused_lines = [
        f"- {item}: refused: {reason}"
        for item, reason in summary["artifacts_refused"].items()
    ] or ["- none"]
    symbol_text = ", ".join(summary["symbols"]) if summary["symbols"] else "none"
    lines = [
        "Hermes historical trade summary",
        "",
        "Artifacts read:",
        *read_lines,
        "",
        "Artifacts missing or unreadable:",
        *missing_lines,
        "",
        "Artifacts refused:",
        *refused_lines,
        "",
        "Historical posture/performance:",
        f"- trade_rows_count: {summary['trade_rows_count']}",
        f"- pnl_rows_count: {summary['pnl_rows_count']}",
        f"- wins_count: {summary['wins_count']}",
        f"- losses_count: {summary['losses_count']}",
        f"- flat_count: {summary['flat_count']}",
        f"- net_realized_pnl: {summary['net_realized_pnl']}",
        f"- avg_realized_pnl: {summary['avg_realized_pnl']}",
        f"- symbols: {symbol_text}",
        f"- performance_trend: {summary['performance_trend']}",
        "",
        "Safety:",
        "- read-only historical artifact summary",
        "- no exchange writes, no live execution, no override/promotion mutation",
        "- not exchange reconciliation",
    ]
    return "\n".join(lines)


def format_json_summary(summary: dict[str, Any]) -> str:
    return json.dumps(summary, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()
    summary = build_historical_trade_summary()
    print(format_json_summary(summary) if args.json else format_text_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
