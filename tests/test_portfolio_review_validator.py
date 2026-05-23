from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.portfolio_review_validator import (  # noqa: E402
    DEFAULT_ARTIFACTS,
    PathRefused,
    build_review,
    validate_artifact_path,
)


def _write_default_artifacts(root: Path) -> None:
    data = root / "data"
    data.mkdir(parents=True)
    payloads = {
        "state.json": {"positions": {}, "entry_paused": False},
        "portfolio_snapshot.json": {
            "strategy": "S01",
            "ts_utc": "2026-05-23T15:01:11Z",
            "holdings": [],
            "exposure_pct": 0.0,
            "entries_allowed": True,
        },
        "open_orders_snapshot.json": {"open_orders": []},
        "telegram_status.json": {"positions": [], "strategy": "S01"},
    }
    for name, payload in payloads.items():
        (data / name).write_text(json.dumps(payload), encoding="utf-8")


def test_default_artifacts_are_allowed(tmp_path: Path) -> None:
    _write_default_artifacts(tmp_path)

    for relative in DEFAULT_ARTIFACTS:
        assert validate_artifact_path(tmp_path, relative) == tmp_path / relative


@pytest.mark.parametrize(
    "relative",
    [
        ".env",
        "data/.env",
        "data/strategy_overrides.json",
        "data/openclaw_report.json",
        "data/promotion_state.json",
        "data/override_state.json",
        "reports/portfolio.json",
        "artifacts/portfolio.json",
        "runs/latest.json",
        "snapshots/latest.json",
        "metrics/latest.json",
        "backtests/latest.json",
        "paper/latest.json",
        "live/latest.json",
        "state/positions.json",
        "data/trades_journal.csv",
    ],
)
def test_refuses_non_default_and_sensitive_paths(tmp_path: Path, relative: str) -> None:
    with pytest.raises(PathRefused):
        validate_artifact_path(tmp_path, relative)


def test_refuses_allowed_name_when_symlinked(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    target = tmp_path / "real_state.json"
    target.write_text("{}", encoding="utf-8")
    (data / "state.json").symlink_to(target)

    with pytest.raises(PathRefused):
        validate_artifact_path(tmp_path, "data/state.json")


def test_build_review_reads_only_default_artifacts(tmp_path: Path) -> None:
    _write_default_artifacts(tmp_path)
    (tmp_path / "data" / "strategy_overrides.json").write_text("{}", encoding="utf-8")

    review = build_review(tmp_path)

    assert sorted(review["artifacts"]) == sorted(path.as_posix() for path in DEFAULT_ARTIFACTS)
    assert all(item["status"] == "read" for item in review["artifacts"].values())
