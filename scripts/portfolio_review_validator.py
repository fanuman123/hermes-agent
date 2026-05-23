#!/usr/bin/env python3
"""Dry-run validator for the Hermes portfolio review process.

The validator intentionally reads only the four current Kraken Bot V2 snapshot
artifacts used by the read-only portfolio review runbook. It does not write
reports, mutate state, inspect OpenClaw, or follow symlinked artifact paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_KRAKEN_ROOT = Path("/opt/bots/kraken-bot-v2")
DEFAULT_ARTIFACTS = (
    Path("data/state.json"),
    Path("data/portfolio_snapshot.json"),
    Path("data/open_orders_snapshot.json"),
    Path("data/telegram_status.json"),
)
REFUSED_TOKENS = (
    ".env",
    "strategy_overrides.json",
    "override",
    "promotion",
    "openclaw",
)


class PathRefused(ValueError):
    """Raised when a path falls outside the dry-run read allowlist."""


def _has_symlink_component(path: Path, stop_at: Path) -> bool:
    current = path
    while current != stop_at and current != current.parent:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def validate_artifact_path(root: Path, requested: Path | str) -> Path:
    """Return an absolute path if requested is one of the four safe artifacts.

    The check is lexical first, then filesystem-aware for existing paths. This
    lets missing allowlisted files be reported as missing while still refusing
    symlinks, OpenClaw paths, override/promotion artifacts, and broad paths.
    """

    requested_path = Path(requested)
    if requested_path.is_absolute():
        try:
            relative = requested_path.relative_to(root)
        except ValueError as exc:
            raise PathRefused(f"outside Kraken Bot V2 root: {requested_path}") from exc
    else:
        relative = requested_path

    normalized = Path(*relative.parts)
    relative_text = normalized.as_posix().lower()

    if normalized not in DEFAULT_ARTIFACTS:
        raise PathRefused(f"non-allowlisted artifact: {normalized.as_posix()}")

    if any(token in relative_text for token in REFUSED_TOKENS):
        raise PathRefused(f"refused sensitive artifact path: {normalized.as_posix()}")

    candidate = root / normalized
    if _has_symlink_component(candidate, root):
        raise PathRefused(f"refused symlink artifact path: {normalized.as_posix()}")

    resolved_root = root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise PathRefused(f"artifact resolves outside Kraken Bot V2 root: {normalized.as_posix()}") from exc

    if "openclaw" in resolved_candidate.as_posix().lower():
        raise PathRefused(f"refused OpenClaw-linked artifact path: {normalized.as_posix()}")

    return candidate


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"invalid json: {exc}"


def build_review(root: Path = DEFAULT_KRAKEN_ROOT) -> dict[str, Any]:
    artifacts: dict[str, dict[str, Any]] = {}
    refused: dict[str, str] = {}

    for relative in DEFAULT_ARTIFACTS:
        try:
            path = validate_artifact_path(root, relative)
        except PathRefused as exc:
            refused[relative.as_posix()] = str(exc)
            continue
        data, error = _load_json(path)
        artifacts[relative.as_posix()] = {
            "path": str(path),
            "status": "read" if error is None else error,
            "data": data,
        }

    return {"root": str(root), "artifacts": artifacts, "refused": refused}


def _portfolio_summary(review: dict[str, Any]) -> list[str]:
    artifacts = review["artifacts"]
    portfolio = artifacts.get("data/portfolio_snapshot.json", {}).get("data") or {}
    open_orders = artifacts.get("data/open_orders_snapshot.json", {}).get("data") or {}
    telegram = artifacts.get("data/telegram_status.json", {}).get("data") or {}
    state = artifacts.get("data/state.json", {}).get("data") or {}

    holdings = portfolio.get("holdings", [])
    orders = open_orders.get("open_orders", [])
    positions = state.get("positions", {})

    return [
        f"strategy: {portfolio.get('strategy') or telegram.get('strategy') or 'unknown'}",
        f"snapshot_ts_utc: {portfolio.get('ts_utc') or open_orders.get('ts_utc') or 'unknown'}",
        f"holdings_count: {len(holdings) if isinstance(holdings, list) else 'unknown'}",
        f"positions_count: {len(positions) if isinstance(positions, dict) else 'unknown'}",
        f"open_orders_count: {len(orders) if isinstance(orders, list) else 'unknown'}",
        f"exposure_pct: {portfolio.get('exposure_pct', telegram.get('exposure_pct', 'unknown'))}",
        f"entries_allowed: {portfolio.get('entries_allowed', telegram.get('entries_allowed', 'unknown'))}",
        f"entry_paused: {state.get('entry_paused', 'unknown')}",
    ]


def print_review(review: dict[str, Any]) -> None:
    print("Hermes dry-run portfolio review validator")
    print(f"Kraken Bot V2 root: {review['root']}")
    print()

    print("Artifacts read:")
    for rel, item in review["artifacts"].items():
        if item["status"] == "read":
            print(f"- {rel}")
    print()

    print("Artifacts missing or unreadable:")
    for rel, item in review["artifacts"].items():
        if item["status"] != "read":
            print(f"- {rel}: {item['status']}")
    for rel, reason in review["refused"].items():
        print(f"- {rel}: refused: {reason}")
    has_unreadable = any(item["status"] != "read" for item in review["artifacts"].values())
    if not has_unreadable and not review["refused"]:
        print("- none")
    print()

    print("Portfolio summary:")
    for line in _portfolio_summary(review):
        print(f"- {line}")
    print()

    print("No-write checklist:")
    print("- read only fixed four Kraken Bot V2 snapshot JSON artifacts")
    print("- did not inspect .env, launchd, secrets, overrides, promotions, or OpenClaw paths")
    print("- did not write reports, mutate runtime state, place orders, deploy, restart, or repair state")
    print("- refused symlink, OpenClaw-linked, override/promotion, and non-allowlisted paths")


def main() -> int:
    print_review(build_review(DEFAULT_KRAKEN_ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
