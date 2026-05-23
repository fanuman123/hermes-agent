from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.historical_trade_summary import (  # noqa: E402
    DEFAULT_TRADE_ARTIFACTS,
    TradeArtifactRefused,
    build_historical_trade_summary,
    format_text_summary,
    validate_trade_artifact_path,
)


def test_historical_trade_summary_reads_bounded_trade_artifacts(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "fills.json").write_text(
        json.dumps(
            {
                "fills": [
                    {"symbol": "SAMPLEUSD", "realized_pnl": "2.5"},
                    {"symbol": "SAMPLEUSD", "realized_pnl": "-1.0"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (data / "trades.csv").write_text(
        "symbol,pnl\nOTHERUSD,0.5\n",
        encoding="utf-8",
    )

    summary = build_historical_trade_summary(tmp_path)

    assert summary["artifacts_read"] == ["data/fills.json", "data/trades.csv"]
    assert set(summary["artifacts_missing_or_unreadable"]) == {
        "data/fills.csv",
        "data/trades.json",
    }
    assert summary["trade_rows_count"] == 3
    assert summary["wins_count"] == 2
    assert summary["losses_count"] == 1
    assert summary["net_realized_pnl"] == 2.0
    assert summary["performance_trend"] == "positive_realized_trend"
    assert summary["symbols"] == ["OTHERUSD", "SAMPLEUSD"]


def test_historical_trade_summary_refuses_non_allowlisted_paths(tmp_path: Path) -> None:
    with pytest.raises(TradeArtifactRefused):
        validate_trade_artifact_path(tmp_path, "data/state.json")
    with pytest.raises(TradeArtifactRefused):
        validate_trade_artifact_path(tmp_path, "data/strategy_overrides.json")


def test_historical_trade_summary_refuses_symlink(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (tmp_path / "real_fills.json").write_text("[]", encoding="utf-8")
    (data / "fills.json").symlink_to(tmp_path / "real_fills.json")

    summary = build_historical_trade_summary(tmp_path, artifacts=(DEFAULT_TRADE_ARTIFACTS[0],))

    assert summary["artifacts_read"] == []
    assert "data/fills.json" in summary["artifacts_refused"]
    assert "symlink" in summary["artifacts_refused"]["data/fills.json"]


def test_historical_trade_summary_text_contains_no_write_guarantee(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "fills.json").write_text("[]", encoding="utf-8")

    text = format_text_summary(build_historical_trade_summary(tmp_path))

    assert "Hermes historical trade summary" in text
    assert "no exchange writes, no live execution, no override/promotion mutation" in text
    assert "not exchange reconciliation" in text
