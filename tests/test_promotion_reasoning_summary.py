from __future__ import annotations

import json
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.promotion_reasoning_summary import (  # noqa: E402
    build_promotion_reasoning_summary,
    format_text_summary,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_kraken_snapshots(
    root: Path,
    *,
    timestamp: str = "2099-01-02T03:04:05Z",
    exposure_pct: object = 0.0,
    entries_allowed: bool = True,
    entry_paused: bool = False,
) -> None:
    _write_json(root / "data" / "state.json", {"positions": {}, "entry_paused": entry_paused})
    _write_json(
        root / "data" / "portfolio_snapshot.json",
        {
            "strategy": "SAMPLE_S01",
            "ts_utc": timestamp,
            "holdings": [],
            "exposure_pct": exposure_pct,
            "entries_allowed": entries_allowed,
        },
    )
    _write_json(root / "data" / "open_orders_snapshot.json", {"open_orders": [], "ts_utc": timestamp})
    _write_json(root / "data" / "telegram_status.json", {"positions": [], "strategy": "SAMPLE_S01"})


def test_promotion_reasoning_healthy_is_only_eligible_for_human_review(tmp_path: Path) -> None:
    _write_kraken_snapshots(tmp_path)

    summary = build_promotion_reasoning_summary(tmp_path)

    assert summary["health_status"] == "HEALTHY"
    assert summary["reasoning_outcome"] == "eligible_for_human_review"
    assert summary["promotion_authority"] is False
    assert summary["override_authority"] is False
    assert summary["no_write_safety"]["writes_overrides"] is False


def test_promotion_reasoning_degraded_gate_needs_review(tmp_path: Path) -> None:
    _write_kraken_snapshots(tmp_path, entries_allowed=False, entry_paused=True)

    summary = build_promotion_reasoning_summary(tmp_path)

    assert summary["health_status"] == "DEGRADED"
    assert summary["reasoning_outcome"] == "review_degraded_inputs"
    assert "entries_allowed is false" in summary["gate_reasons"]
    assert "entry_paused is true" in summary["gate_reasons"]


def test_promotion_reasoning_attention_required_blocks_use(tmp_path: Path) -> None:
    _write_kraken_snapshots(tmp_path, exposure_pct="not-a-number")

    summary = build_promotion_reasoning_summary(tmp_path)

    assert summary["health_status"] == "ATTENTION_REQUIRED"
    assert summary["reasoning_outcome"] == "blocked_pending_human_review"
    assert any("do not use for promotion or override decisions" in reason for reason in summary["reasoning_reasons"])


def test_promotion_reasoning_refusal_inherited_from_snapshot_validator(tmp_path: Path) -> None:
    _write_kraken_snapshots(tmp_path)
    (tmp_path / "data" / "state.json").unlink()
    (tmp_path / "data" / "state.json").symlink_to(tmp_path / "real_state.json")

    summary = build_promotion_reasoning_summary(tmp_path)

    assert summary["health_status"] == "ATTENTION_REQUIRED"
    assert "data/state.json" in summary["artifacts_refused"]
    assert "required Kraken Bot V2 snapshot artifact refused" in summary["gate_reasons"]


def test_promotion_reasoning_text_contains_no_write_guarantee(tmp_path: Path) -> None:
    _write_kraken_snapshots(tmp_path)

    text = format_text_summary(build_promotion_reasoning_summary(tmp_path))

    assert "Hermes promotion/override reasoning summary" in text
    assert "advisory-only and human-review-only" in text
    assert "no promotion execution and no override mutation" in text
