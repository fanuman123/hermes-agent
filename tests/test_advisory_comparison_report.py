from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.advisory_comparison_report import (  # noqa: E402
    OpenClawArtifactRefused,
    build_advisory_comparison_report,
    format_text_report,
    validate_openclaw_artifact_path,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_kraken_snapshots(root: Path, *, positions: dict[str, object] | None = None) -> None:
    _write_json(root / "data" / "state.json", {"positions": positions or {}, "entry_paused": False})
    _write_json(
        root / "data" / "portfolio_snapshot.json",
        {
            "strategy": "SAMPLE_S01",
            "ts_utc": "2099-01-02T03:04:05Z",
            "holdings": [],
            "exposure_pct": 0.0,
            "entries_allowed": True,
        },
    )
    _write_json(root / "data" / "open_orders_snapshot.json", {"open_orders": [], "ts_utc": "2099-01-02T03:04:05Z"})
    _write_json(root / "data" / "telegram_status.json", {"positions": list((positions or {}).keys()), "strategy": "SAMPLE_S01"})


def test_advisory_comparison_reads_only_bounded_openclaw_artifacts(tmp_path: Path) -> None:
    kraken_root = tmp_path / "kraken"
    openclaw_root = tmp_path / "openclaw"
    _write_kraken_snapshots(kraken_root)
    _write_json(
        openclaw_root / "data" / "reports" / "latest" / "facts.json",
        {"posture": {"live_flat": True}},
    )
    _write_json(
        openclaw_root / "data" / "reports" / "latest" / "operator_context.json",
        {"paper_freshness_status": "fresh"},
    )
    (openclaw_root / "data" / "reports" / "latest" / "operator_summary.md").write_text(
        "# SAMPLE ONLY\n",
        encoding="utf-8",
    )

    report = build_advisory_comparison_report(kraken_root, openclaw_root)

    assert report["hermes_posture"] == "FLAT"
    assert report["legacy_openclaw_posture"] == "FLAT"
    assert report["posture_match"] is True
    assert report["legacy_artifacts_read"] == [
        "data/reports/latest/operator_context.json",
        "data/reports/latest/facts.json",
        "data/reports/latest/operator_summary.md",
    ]
    assert report["no_write_safety"]["comparison_only"] is True


def test_advisory_comparison_reports_missing_legacy_artifacts(tmp_path: Path) -> None:
    kraken_root = tmp_path / "kraken"
    openclaw_root = tmp_path / "openclaw"
    _write_kraken_snapshots(kraken_root)

    report = build_advisory_comparison_report(kraken_root, openclaw_root)

    assert report["legacy_openclaw_posture"] == "LEGACY_MISSING"
    assert set(report["legacy_artifacts_missing_or_unreadable"]) == {
        "data/reports/latest/operator_context.json",
        "data/reports/latest/facts.json",
        "data/reports/latest/operator_summary.md",
    }


def test_advisory_comparison_refuses_non_allowlisted_openclaw_paths(tmp_path: Path) -> None:
    with pytest.raises(OpenClawArtifactRefused):
        validate_openclaw_artifact_path(tmp_path, "data/reports/latest/strategy_overrides.json")
    with pytest.raises(OpenClawArtifactRefused):
        validate_openclaw_artifact_path(tmp_path, "data/reports/latest/promotion.json")


def test_advisory_comparison_refuses_symlink(tmp_path: Path) -> None:
    kraken_root = tmp_path / "kraken"
    openclaw_root = tmp_path / "openclaw"
    _write_kraken_snapshots(kraken_root)
    target = tmp_path / "operator_context.json"
    target.write_text("{}", encoding="utf-8")
    artifact = openclaw_root / "data" / "reports" / "latest" / "operator_context.json"
    artifact.parent.mkdir(parents=True)
    artifact.symlink_to(target)

    report = build_advisory_comparison_report(
        kraken_root,
        openclaw_root,
        openclaw_artifacts=(Path("data/reports/latest/operator_context.json"),),
    )

    assert report["legacy_artifacts_read"] == []
    assert "data/reports/latest/operator_context.json" in report["legacy_artifacts_refused"]
    assert report["legacy_openclaw_posture"] == "LEGACY_REFUSED"


def test_advisory_comparison_text_is_human_review_only(tmp_path: Path) -> None:
    kraken_root = tmp_path / "kraken"
    openclaw_root = tmp_path / "openclaw"
    _write_kraken_snapshots(kraken_root)

    text = format_text_report(build_advisory_comparison_report(kraken_root, openclaw_root))

    assert "Hermes advisory comparison report" in text
    assert "comparison-only, human-review-only" in text
    assert "no promotion authority, no override writes, no exchange writes" in text
