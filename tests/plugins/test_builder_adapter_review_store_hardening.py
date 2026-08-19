from __future__ import annotations

import os
import sqlite3
import threading
import time

import pytest
from pydantic import ValidationError

from plugins.builder_adapter.errors import AdapterError
from plugins.builder_adapter.review_orchestrator import (
    ReviewStore,
    TestResult as VerificationTestResult,
    TransitionRequest,
)
from plugins.builder_adapter.review_receipts import ReceiptAuthority


CAPSULE_SECRET = b"anchor-hardening-capsule-secret-32b"


def _authority():
    return ReceiptAuthority(capsule_checkpoint_secret=CAPSULE_SECRET)


def _record(job_id: str) -> dict:
    return {
        "job_id": job_id,
        "phase": "QUEUED",
        "status": "ACTIVE",
        "repository_id": "local/repository",
        "starting_sha": "a" * 40,
    }


def _create(store: ReviewStore, job_id: str) -> None:
    store.create(job_id, "hermes", "b" * 64, _record(job_id))


def test_persisted_operator_text_is_bounded_and_secret_redacted():
    test = VerificationTestResult(
        scope="focused",
        status="PASSED",
        command="pytest --token=operator-secret",
        summary="Authorization: Bearer summary-secret",
        ran_at="2026-08-18T00:00:00Z",
    )
    transition = TransitionRequest(
        target_phase="BLOCKED",
        next_action="retry token=next-secret",
        block_reason="password=block-secret",
    )

    assert "operator-secret" not in test.command
    assert "summary-secret" not in test.summary
    assert transition.next_action is not None
    assert transition.block_reason is not None
    assert "next-secret" not in transition.next_action
    assert "block-secret" not in transition.block_reason
    assert all(
        "[REDACTED]" in value
        for value in (
            test.command,
            test.summary,
            transition.next_action,
            transition.block_reason,
        )
    )

    with pytest.raises(ValidationError):
        VerificationTestResult(
            scope="full",
            status="UNKNOWN",
            command="x" * 2049,
            ran_at="2026-08-18T00:00:00Z",
        )
    with pytest.raises(ValidationError):
        TransitionRequest(target_phase="BLOCKED", block_reason="x" * 2049)


@pytest.mark.parametrize(
    "ran_at",
    [
        "token=timestamp-secret",
        "2026-08-18T00:00:00+00:00",
        "2026-08-18T00:00:00.1Z",
        "2026-08-18 00:00:00Z",
    ],
)
def test_persisted_test_timestamp_requires_canonical_utc(ran_at):
    with pytest.raises(ValidationError):
        VerificationTestResult(
            scope="focused",
            status="PASSED",
            command="pytest",
            ran_at=ran_at,
        )


def test_review_store_rejects_non_owner_only_parent(tmp_path):
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    parent.chmod(0o755)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(parent / "review.db")

    assert raised.value.code == "STORE_PATH_INVALID"


def test_review_store_rejects_permissive_existing_database(tmp_path):
    database = tmp_path / "review.db"
    sqlite3.connect(database).close()
    database.chmod(0o644)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database)

    assert raised.value.code == "STORE_PATH_INVALID"


def test_review_store_rejects_database_symlink(tmp_path):
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    target.chmod(0o600)
    database = tmp_path / "review.db"
    database.symlink_to(target)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database)

    assert raised.value.code == "STORE_PATH_INVALID"


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires no-follow support")
def test_review_store_rejects_preexisting_sidecar_symlink(tmp_path):
    database = tmp_path / "review.db"
    database.touch(mode=0o600)
    target = tmp_path / "target"
    target.write_bytes(b"")
    target.chmod(0o600)
    (tmp_path / "review.db-wal").symlink_to(target)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database)

    assert raised.value.code == "STORE_PATH_INVALID"


def test_missing_anchor_never_reanchors_initialized_store(tmp_path):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")
    store.anchor_path.unlink()

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)

    assert raised.value.code == "AUDIT_ROLLBACK"
    assert not store.anchor_path.exists()


def test_schema_only_trigger_tamper_is_detected_on_reopen(tmp_path):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")

    with sqlite3.connect(database) as conn:
        conn.execute("DROP TRIGGER review_validation_receipts_immutable_delete")

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)

    assert raised.value.code == "AUDIT_ROLLBACK"


def test_preexisting_empty_database_is_not_brand_new_initialization(tmp_path):
    database = tmp_path / "review.db"
    database.touch(mode=0o600)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=_authority())

    assert raised.value.code == "AUDIT_ROLLBACK"


@pytest.mark.parametrize(
    ("point", "committed"),
    [
        ("after_intent_before_commit", False),
        ("after_commit_before_finalize", True),
    ],
)
def test_signed_pending_intent_recovers_only_provable_crash_state(
    tmp_path, monkeypatch, point, committed
):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")

    def crash(selected):
        if selected == point:
            raise RuntimeError("simulated process loss")

    monkeypatch.setattr(store, "_fault_inject", crash)
    with pytest.raises(RuntimeError, match="simulated process loss"):
        _create(store, "job-two")
    assert store.pending_anchor_path.exists()

    recovered = ReviewStore(database, authority=authority)
    assert recovered.get("job-two") is not None if committed else recovered.get("job-two") is None
    assert not recovered.pending_anchor_path.exists()
    recovered._verify_anchor_chain()


@pytest.mark.parametrize("statement_index", [0, 3, 8, 15])
def test_first_schema_creation_recovers_from_arbitrary_statement_crash(
    tmp_path, monkeypatch, statement_index
):
    authority = _authority()
    database = tmp_path / "review.db"
    original = ReviewStore._fault_inject

    def crash(_self, point):
        if point == f"after_schema_statement:{statement_index}":
            raise RuntimeError("simulated schema crash")

    monkeypatch.setattr(ReviewStore, "_fault_inject", crash)
    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)
    assert raised.value.code == "UNSUPPORTED_SCHEMA"

    monkeypatch.setattr(ReviewStore, "_fault_inject", original)
    recovered = ReviewStore(database, authority=authority)
    _create(recovered, "job-after-schema-recovery")
    assert recovered.get("job-after-schema-recovery") is not None


def test_signed_pending_intent_repairs_torn_anchor_after_database_commit(
    tmp_path, monkeypatch
):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")

    def crash(point):
        if point == "after_commit_before_finalize":
            raise RuntimeError("simulated process loss")

    monkeypatch.setattr(store, "_fault_inject", crash)
    with pytest.raises(RuntimeError):
        _create(store, "job-two")
    store.anchor_path.write_bytes(b'{"torn":')
    store.anchor_path.chmod(0o600)

    recovered = ReviewStore(database, authority=authority)
    assert recovered.get("job-two") is not None
    assert not recovered.pending_anchor_path.exists()
    recovered._verify_anchor_chain()


def test_anchor_checkpoint_is_bounded_after_many_generations(tmp_path):
    store = ReviewStore(tmp_path / "review.db", authority=_authority())
    for index in range(300):
        _create(store, f"job-{index}")

    assert store.anchor_path.stat().st_size < 4096
    assert len(store._read_anchors()) == 1


def test_pending_intent_with_unrelated_database_state_fails_closed(tmp_path, monkeypatch):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")

    def crash(point):
        if point == "after_intent_before_commit":
            raise RuntimeError("simulated process loss")

    monkeypatch.setattr(store, "_fault_inject", crash)
    with pytest.raises(RuntimeError):
        _create(store, "job-two")
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE review_meta SET value='unrelated' WHERE key='schema_version'")

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_append_only_anchor_detects_stale_history(tmp_path):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")
    old_history = store.anchor_path.read_bytes()
    _create(store, "job-two")
    store.anchor_path.write_bytes(old_history)
    store.anchor_path.chmod(0o600)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_append_only_anchor_detects_future_history_against_old_database(tmp_path):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")
    old_database = tmp_path / "old.db"
    with sqlite3.connect(database) as source, sqlite3.connect(old_database) as target:
        source.backup(target)
    old_database.chmod(0o600)
    _create(store, "job-two")
    future_history = store.anchor_path.read_bytes()
    with sqlite3.connect(old_database) as source, sqlite3.connect(database) as target:
        source.backup(target)
    assert store.anchor_path.read_bytes() == future_history

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_deleted_anchor_and_restored_old_database_fail_closed(tmp_path):
    authority = _authority()
    database = tmp_path / "review.db"
    store = ReviewStore(database, authority=authority)
    _create(store, "job-one")
    old_database = tmp_path / "old.db"
    with sqlite3.connect(database) as source, sqlite3.connect(old_database) as target:
        source.backup(target)
    old_database.chmod(0o600)
    _create(store, "job-two")
    with sqlite3.connect(old_database) as source, sqlite3.connect(database) as target:
        source.backup(target)
    store.anchor_path.unlink()

    with pytest.raises(AdapterError) as raised:
        ReviewStore(database, authority=authority)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_concurrent_opener_waits_for_commit_and_anchor_publication(tmp_path, monkeypatch):
    authority = _authority()
    database = tmp_path / "review.db"
    mutator = ReviewStore(database, authority=authority)
    _create(mutator, "job-one")
    entered = threading.Event()
    release = threading.Event()
    opened = threading.Event()
    errors = []

    def pause(point):
        if point == "after_commit_before_finalize":
            entered.set()
            assert release.wait(timeout=5)

    monkeypatch.setattr(mutator, "_fault_inject", pause)

    def mutate():
        try:
            _create(mutator, "job-two")
        except Exception as exc:  # pragma: no cover - asserted through errors
            errors.append(exc)

    def open_store():
        try:
            reopened = ReviewStore(database, authority=authority)
            assert reopened.get("job-two") is not None
            opened.set()
        except Exception as exc:  # pragma: no cover - asserted through errors
            errors.append(exc)

    mutation = threading.Thread(target=mutate)
    mutation.start()
    assert entered.wait(timeout=5)
    opener = threading.Thread(target=open_store)
    opener.start()
    time.sleep(0.1)
    assert not opened.is_set()
    release.set()
    mutation.join(timeout=5)
    opener.join(timeout=5)
    assert not errors
    assert opened.is_set()
