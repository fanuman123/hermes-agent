from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
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
    timestamp: str = "2099-01-02T03:04:05Z",
    include_timestamp: bool = True,
    telegram_positions: list[str] | None = None,
) -> None:
    _write_json(
        root / "data" / "state.json",
        {"positions": positions or {}, "entry_paused": entry_paused},
    )
    portfolio = {
            "strategy": "SAMPLE_S01",
            "holdings": holdings or [],
            "exposure_pct": exposure_pct,
            "entries_allowed": entries_allowed,
        }
    if include_timestamp:
        portfolio["ts_utc"] = timestamp
    _write_json(root / "data" / "portfolio_snapshot.json", portfolio)
    _write_json(
        root / "data" / "open_orders_snapshot.json",
        {"open_orders": open_orders or [], "ts_utc": timestamp} if include_timestamp else {"open_orders": open_orders or []},
    )
    _write_json(
        root / "data" / "telegram_status.json",
        {"positions": telegram_positions if telegram_positions is not None else list((positions or {}).keys()), "strategy": "SAMPLE_S01"},
    )


def _now() -> datetime:
    return datetime(2099, 1, 2, 3, 14, 5, tzinfo=timezone.utc)


def test_flat_portfolio_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["strategy"] == "SAMPLE_S01"
    assert report["holdings_count"] == 0
    assert report["positions_count"] == 0
    assert report["open_orders_count"] == 0
    assert report["exposure_pct"] == 0.0
    assert report["entries_allowed"] is True
    assert report["entry_paused"] is False
    assert report["posture"] == "FLAT"
    assert report["freshness_status"] == "fresh"
    assert report["data_age_minutes"] == 10.0
    assert report["health_status"] == "HEALTHY"
    assert report["health_reasons"] == []
    assert report["recommended_operator_action"] == "observe"


def test_open_position_report_is_active(tmp_path: Path) -> None:
    _write_artifacts(
        tmp_path,
        holdings=[{"symbol": "SAMPLEUSDC", "value_usdc": 42.0}],
        positions={"SAMPLEUSDC": {"qty": 1.0}},
        open_orders=[{"symbol": "SAMPLEUSDC", "side": "sell"}],
        exposure_pct=12.5,
    )

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["holdings_count"] == 1
    assert report["positions_count"] == 1
    assert report["open_orders_count"] == 1
    assert report["posture"] == "ACTIVE"
    assert report["recommended_operator_action"] == "investigate"
    assert report["health_status"] == "HEALTHY"


def test_stale_sample_is_degraded(tmp_path: Path) -> None:
    stale_timestamp = (_now() - timedelta(minutes=45)).isoformat().replace("+00:00", "Z")
    _write_artifacts(tmp_path, timestamp=stale_timestamp)

    report = build_operator_report(tmp_path, now_utc=_now(), stale_after_minutes=30)

    assert report["freshness_status"] == "stale"
    assert report["data_age_minutes"] == 45.0
    assert report["health_status"] == "DEGRADED"
    assert report["recommended_operator_action"] == "investigate"


def test_missing_timestamp_sample_is_degraded(tmp_path: Path) -> None:
    _write_artifacts(tmp_path, include_timestamp=False)

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["freshness_status"] == "missing_timestamp"
    assert report["data_age_minutes"] is None
    assert report["health_status"] == "DEGRADED"
    assert report["recommended_operator_action"] == "investigate"


def test_invalid_timestamp_sample_requires_attention(tmp_path: Path) -> None:
    _write_artifacts(tmp_path, timestamp="not-a-timestamp")

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["freshness_status"] == "invalid_timestamp"
    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert report["recommended_operator_action"] == "pause-review-needed"


def test_unreadable_json_sample_requires_attention(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "portfolio_snapshot.json").write_text("{", encoding="utf-8")

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert report["recommended_operator_action"] == "pause-review-needed"
    assert report["artifacts_missing_or_unreadable"]["data/portfolio_snapshot.json"].startswith("invalid json")


def test_missing_artifact_report_requires_attention(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "open_orders_snapshot.json").unlink()

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert report["recommended_operator_action"] == "pause-review-needed"
    assert report["artifacts_missing_or_unreadable"] == {
        "data/open_orders_snapshot.json": "missing"
    }


def test_exposure_parse_failure_requires_attention(tmp_path: Path) -> None:
    _write_artifacts(tmp_path, exposure_pct="not-a-number")  # type: ignore[arg-type]

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["exposure_pct"] is None
    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert report["recommended_operator_action"] == "pause-review-needed"


def test_conflicting_position_counts_require_attention(tmp_path: Path) -> None:
    _write_artifacts(
        tmp_path,
        positions={"SAMPLEUSDC": {"qty": 1.0}},
        telegram_positions=[],
    )

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert report["recommended_operator_action"] == "pause-review-needed"


def test_refusal_safety_behavior_is_inherited(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "state.json").unlink()
    (tmp_path / "data" / "state.json").symlink_to(tmp_path / "real_state.json")

    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["posture"] == "DEGRADED"
    assert report["health_status"] == "ATTENTION_REQUIRED"
    assert "data/state.json" in report["artifacts_refused"]
    assert "symlink" in report["artifacts_refused"]["data/state.json"]


def test_text_report_is_operator_friendly(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    text = format_text_report(build_operator_report(tmp_path, now_utc=_now()))

    assert "Hermes Kraken Bot V2 operator report" in text
    assert "posture: FLAT" in text
    assert "freshness_status: fresh" in text
    assert "data_age_minutes: 10.0" in text
    assert "health_status: HEALTHY" in text
    assert "health_reasons:" in text
    assert "recommended_operator_action: observe" in text
    assert "Kraken Bot V2 remains execution authority" in text
    assert "no writes, no orders, no OpenClaw, no overrides/promotions" in text


def test_json_report_fields(tmp_path: Path) -> None:
    _write_artifacts(tmp_path, positions={"SAMPLEUSDC": {"qty": 1.0}}, exposure_pct=5.0)
    report = build_operator_report(tmp_path, now_utc=_now())

    assert report["posture"] == "ACTIVE"
    assert report["recommended_operator_action"] == "investigate"
    assert report["no_write_safety"]["places_orders"] is False


def test_json_mode_emits_machine_readable_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    payload = json.loads(format_json_report(build_operator_report(tmp_path, now_utc=_now())))

    assert "strategy" in payload
    assert "posture" in payload
    assert "freshness_status" in payload
    assert "data_age_minutes" in payload
    assert "health_status" in payload
    assert "health_reasons" in payload
    assert "recommended_operator_action" in payload
    assert payload["no_write_safety"]["places_orders"] is False
