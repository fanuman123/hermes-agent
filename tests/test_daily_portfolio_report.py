from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.daily_portfolio_report import (  # noqa: E402
    OutputPathRefused,
    build_daily_report,
    format_json_daily_report,
    format_markdown_report,
    resolve_output_path,
    write_report,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _now() -> datetime:
    return datetime(2099, 1, 2, 3, 14, 5, tzinfo=timezone.utc)


def _write_artifacts(
    root: Path,
    *,
    holdings: list[dict[str, object]] | None = None,
    positions: dict[str, object] | None = None,
    open_orders: list[dict[str, object]] | None = None,
    exposure_pct: object = 0.0,
    timestamp: str = "2099-01-02T03:04:05Z",
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
            "ts_utc": timestamp,
            "holdings": holdings or [],
            "exposure_pct": exposure_pct,
            "entries_allowed": entries_allowed,
        },
    )
    _write_json(
        root / "data" / "open_orders_snapshot.json",
        {"open_orders": open_orders or [], "ts_utc": timestamp},
    )
    _write_json(
        root / "data" / "telegram_status.json",
        {"positions": list((positions or {}).keys()), "strategy": "SAMPLE_S01"},
    )


def test_flat_daily_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    report = build_daily_report(tmp_path, now_utc=_now())
    markdown = format_markdown_report(report)

    assert report["report_date"] == "2099-01-02"
    assert report["operator_report"]["posture"] == "FLAT"
    assert report["operator_report"]["health_status"] == "HEALTHY"
    assert "Recommended Human Action" in markdown
    assert "`observe`" in markdown


def test_active_open_position_daily_report(tmp_path: Path) -> None:
    _write_artifacts(
        tmp_path,
        holdings=[{"symbol": "SAMPLEUSDC", "value_usdc": 42.0}],
        positions={"SAMPLEUSDC": {"qty": 1.0}},
        open_orders=[{"symbol": "SAMPLEUSDC", "side": "sell"}],
        exposure_pct=12.5,
    )

    report = build_daily_report(tmp_path, now_utc=_now())
    markdown = format_markdown_report(report)

    assert report["operator_report"]["posture"] == "ACTIVE"
    assert report["operator_report"]["recommended_operator_action"] == "investigate"
    assert "Open positions visible in snapshots: `1`" in markdown
    assert "Open orders visible in snapshots: `1`" in markdown


def test_stale_degraded_daily_report(tmp_path: Path) -> None:
    stale = (_now() - timedelta(minutes=45)).isoformat().replace("+00:00", "Z")
    _write_artifacts(tmp_path, timestamp=stale)

    report = build_daily_report(tmp_path, now_utc=_now(), stale_after_minutes=30)
    markdown = format_markdown_report(report)

    assert report["operator_report"]["freshness_status"] == "stale"
    assert report["operator_report"]["health_status"] == "DEGRADED"
    assert "`investigate`" in markdown


def test_missing_artifact_daily_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)
    (tmp_path / "data" / "open_orders_snapshot.json").unlink()

    report = build_daily_report(tmp_path, now_utc=_now())

    assert report["operator_report"]["health_status"] == "ATTENTION_REQUIRED"
    assert report["operator_report"]["recommended_operator_action"] == "pause-review-needed"


def test_output_path_refusal_outside_hermes_reports(tmp_path: Path) -> None:
    with pytest.raises(OutputPathRefused):
        resolve_output_path(tmp_path / "outside.md", repo_root=tmp_path)

    with pytest.raises(OutputPathRefused):
        resolve_output_path("reports/../outside.md", repo_root=tmp_path)


def test_output_path_allowed_under_reports_daily(tmp_path: Path) -> None:
    destination = write_report("sample", "reports/daily/sample.md", repo_root=tmp_path)

    assert destination == tmp_path / "reports" / "daily" / "sample.md"
    assert destination.read_text(encoding="utf-8") == "sample"


def test_no_write_safety_footer_present(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    markdown = format_markdown_report(build_daily_report(tmp_path, now_utc=_now()))

    assert "Read-only Hermes report." in markdown
    assert "Kraken Bot V2 remains the only execution authority." in markdown
    assert "This is not exchange reconciliation." in markdown


def test_json_daily_report(tmp_path: Path) -> None:
    _write_artifacts(tmp_path)

    payload = json.loads(format_json_daily_report(build_daily_report(tmp_path, now_utc=_now())))

    assert payload["report_date"] == "2099-01-02"
    assert payload["not_exchange_reconciliation"] is True
    assert payload["operator_report"]["health_status"] == "HEALTHY"
