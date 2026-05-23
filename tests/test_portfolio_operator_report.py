from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_SCRIPTS = _REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from scripts.portfolio_operator_report import (  # noqa: E402
    build_operator_report,
    format_json_report,
    format_text_report,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_artifacts(
    root: Path,
    *,
    holdings: list[dict[str, object]] | None = None,
    positions: dict[str, object] | None = None,
    open_orders: list[dict[str, object]] | None = None,
    exposure_pct: float = 0.0,
    entries_allowed: bool = True,
    entry_paused: bool = False,
) -> None:
    _write_json(
        root / "data" / "state.json",
        {"positions": positions or {}, "entry_paused": entry_paused},
    )
    _write_json(
        root / "data" / "portfolio_snapshot.json",
        {
            "strategy": "SAMPLE_S01",
            "ts_utc": "2099-01-02T03:04:05Z",
            "holdings": holdings or [],
            "exposure_pct": exposure_pct,
            "entries_allowed": entries_allowed,
        },
    )
    _write_json(
        root / "data" / "open_orders_snapshot.json",
        {"open_orders": open_orders or [], "ts_utc": "2099-01-02T03:04:05Z"},
    )
    _write_json(
        root / "data" / "telegram_status.json",
        {"positions": list((positions or {}).keys()), "strategy": "SAMPLE_S01"},
    )


def test_flat_portfolio_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    report = build_operator_report(tmp_path)

    assert report["strategy"] == "SAMPLE_S01"
    assert report["holdings_count"] == 0
    assert report["positions_count"] == 0
    assert report["open_orders_count"] == 0
    assert report["exposure_pct"] == 0.0
    assert report["entries_allowed"] is True
    assert report["entry_paused"] is False
    assert report["posture"] == "FLAT"
    assert report["recommended_operator_action"] == "observe"


def test_open_position_report_is_active(tmp_path: Path) -> None:
    _write_artifacts(
        tmp_path,
        holdings=[{"symbol": "SAMPLEUSDC", "value_usdc": 42.0}],
        positions={"SAMPLEUSDC": {"qty": 1.0}},
        open_orders=[{"symbol": "SAMPLEUSDC", "side": "sell"}],
        exposure_pct=12.5,
    )

    report = build_operator_report(tmp_path)

    assert report["holdings_count"] == 1
    assert report["positions_count"] == 1
    assert report["open_orders_count"] == 1
    assert report["posture"] == "ACTIVE"
    assert report["recommended_operator_action"] == "investigate"


def test_missing_artifact_report_is_degraded(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "open_orders_snapshot.json").unlink()

    report = build_operator_report(tmp_path)

    assert report["posture"] == "DEGRADED"
    assert report["recommended_operator_action"] == "investigate"
    assert report["artifacts_missing_or_unreadable"] == {
        "data/open_orders_snapshot.json": "missing"
    }


def test_refusal_safety_behavior_is_inherited(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "state.json").unlink()
    (tmp_path / "data" / "state.json").symlink_to(tmp_path / "real_state.json")

    report = build_operator_report(tmp_path)

    assert report["posture"] == "DEGRADED"
    assert "data/state.json" in report["artifacts_refused"]
    assert "symlink" in report["artifacts_refused"]["data/state.json"]


def test_text_report_is_operator_friendly(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    text = format_text_report(build_operator_report(tmp_path))

    assert "Hermes Kraken Bot V2 operator report" in text
    assert "posture: FLAT" in text
    assert "recommended_operator_action: observe" in text
    assert "Kraken Bot V2 remains execution authority" in text
    assert "no writes, no orders, no OpenClaw, no overrides/promotions" in text


def test_json_report_fields(tmp_path: Path) -> None:
    _write_artifacts(tmp_path, positions={"SAMPLEUSDC": {"qty": 1.0}}, exposure_pct=5.0)
    report = build_operator_report(tmp_path)

    assert report["posture"] == "ACTIVE"
    assert report["recommended_operator_action"] == "investigate"
    assert report["no_write_safety"]["places_orders"] is False


def test_json_mode_emits_machine_readable_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    payload = json.loads(format_json_report(build_operator_report(tmp_path)))

    assert "strategy" in payload
    assert "posture" in payload
    assert "recommended_operator_action" in payload
    assert payload["no_write_safety"]["places_orders"] is False
