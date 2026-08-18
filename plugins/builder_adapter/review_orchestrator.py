"""Persistent review-orchestration control plane for governed builder jobs.

Adds a durable, restartable state machine on top of the existing builder
adapter so a single V4 job can be observed and resumed through::

    QUEUED -> IMPLEMENTING -> REVIEWING -> FIXING -> VERIFYING
            -> READY_FOR_GPT_VALIDATION -> COMPLETE

with ``BLOCKED`` (recoverable) and ``FAILED`` (terminal) handling.

Trust model (enforced, not advisory):

* Every gate is driven by an adapter-issued, single-use, snapshot-bound
  challenge whose snapshot is observed server-side through the existing
  :class:`~.gitops.GitVerifier` repository boundary -- never from the caller's
  own before/after strings.
* A review may only complete through a **runner receipt** minted by the
  adapter's read-only Codex execution boundary (runner-only HMAC secret).
* Verification may only complete through a **validation receipt** minted by
  the validator-only capability after the isolated validation path has run.
  Ordinary Hermes principals cannot mint either receipt: they can only submit
  an opaque, already-minted receipt, whose authenticity the orchestrator
  re-verifies against the runner/validator secret.

Ownership:

* ``hermes`` owns orchestration (create/transition/verification/capsule).
* ``deepseek`` owns ``IMPLEMENTING`` and ``FIXING``.
* ``codex_mcp`` owns ``REVIEWING`` and is the only actor that may submit a
  review-runner receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

import fcntl  # windows-footgun: ok -- review store is a POSIX-only service boundary

from pydantic import Field, ValidationError, field_validator

from .canonical import canonical_json_bytes, canonical_sha256, sha256_bytes
from .errors import AdapterError
from .gitops import GitVerifier
from .models import StrictModel
from .review_receipts import (
    ReceiptAuthority,
    ReceiptFinding,
    ReviewRunnerReceipt,
    ValidationRunnerReceipt,
    redact,
    redact_secrets,
    validation_evidence_material,
)

SCHEMA_VERSION = "1.3.0"
PREVIOUS_SCHEMA_VERSION = "1.2.0"
OPERATION_SCHEMA_VERSION = "1.1.0"
PRIOR_SCHEMA_VERSION = "1.0.0"

# ── Roles ────────────────────────────────────────────────────────────────────
ACTOR_HERMES = "hermes"
ACTOR_DEEPSEEK = "deepseek"
ACTOR_CODEX = "codex_mcp"

# ── Phases ───────────────────────────────────────────────────────────────────
PHASE_QUEUED = "QUEUED"
PHASE_IMPLEMENTING = "IMPLEMENTING"
PHASE_REVIEWING = "REVIEWING"
PHASE_FIXING = "FIXING"
PHASE_VERIFYING = "VERIFYING"
PHASE_READY = "READY_FOR_GPT_VALIDATION"
PHASE_COMPLETE = "COMPLETE"
PHASE_BLOCKED = "BLOCKED"
PHASE_FAILED = "FAILED"

PHASES = frozenset(
    {
        PHASE_QUEUED,
        PHASE_IMPLEMENTING,
        PHASE_REVIEWING,
        PHASE_FIXING,
        PHASE_VERIFYING,
        PHASE_READY,
        PHASE_COMPLETE,
        PHASE_BLOCKED,
        PHASE_FAILED,
    }
)

TERMINAL_PHASES = frozenset({PHASE_COMPLETE, PHASE_FAILED})

# ── Statuses ─────────────────────────────────────────────────────────────────
STATUS_ACTIVE = "ACTIVE"
STATUS_REVIEW_INCOMPLETE = "REVIEW_INCOMPLETE"
STATUS_BLOCKED = "BLOCKED"
STATUS_FAILED = "FAILED"
STATUS_COMPLETE = "COMPLETE"
STATUS_READY = "READY_FOR_GPT_VALIDATION"

STATUSES = frozenset(
    {
        STATUS_ACTIVE,
        STATUS_REVIEW_INCOMPLETE,
        STATUS_BLOCKED,
        STATUS_FAILED,
        STATUS_COMPLETE,
        STATUS_READY,
    }
)

# ── Phase ownership ──────────────────────────────────────────────────────────
PHASE_OWNER = {
    PHASE_IMPLEMENTING: ACTOR_DEEPSEEK,
    PHASE_FIXING: ACTOR_DEEPSEEK,
    PHASE_REVIEWING: ACTOR_CODEX,
    PHASE_VERIFYING: ACTOR_HERMES,
}

# Edges the Hermes-owned ``transition`` operation may drive directly.  Edges
# that cross a gate (REVIEWING -> VERIFYING, VERIFYING -> READY) are excluded:
# those may only be produced by the owning actor's record operation.
ORCHESTRATOR_TRANSITIONS: dict[str, frozenset[str]] = {
    PHASE_QUEUED: frozenset({PHASE_IMPLEMENTING, PHASE_FAILED}),
    PHASE_IMPLEMENTING: frozenset({PHASE_REVIEWING, PHASE_BLOCKED, PHASE_FAILED}),
    PHASE_REVIEWING: frozenset({PHASE_BLOCKED, PHASE_FAILED}),
    PHASE_FIXING: frozenset({PHASE_REVIEWING, PHASE_BLOCKED, PHASE_FAILED}),
    PHASE_VERIFYING: frozenset({PHASE_BLOCKED, PHASE_FAILED}),
    PHASE_READY: frozenset({PHASE_COMPLETE, PHASE_FAILED}),
    PHASE_COMPLETE: frozenset(),
    PHASE_BLOCKED: frozenset(
        {
            PHASE_IMPLEMENTING,
            PHASE_REVIEWING,
            PHASE_FIXING,
            PHASE_VERIFYING,
            PHASE_FAILED,
        }
    ),
    PHASE_FAILED: frozenset(),
}

# ── Challenges ───────────────────────────────────────────────────────────────
CHALLENGE_KIND_REVIEW = "review"
CHALLENGE_KIND_VERIFICATION = "verification"
CHALLENGE_STATUS_ACTIVE = "ACTIVE"
CHALLENGE_STATUS_CONSUMED = "CONSUMED"
CHALLENGE_STATUS_REVOKED = "REVOKED"
CHALLENGE_STATUS_EXPIRED = "EXPIRED"
CHALLENGE_STATUSES = frozenset(
    {
        CHALLENGE_STATUS_ACTIVE,
        CHALLENGE_STATUS_CONSUMED,
        CHALLENGE_STATUS_REVOKED,
        CHALLENGE_STATUS_EXPIRED,
    }
)
CHALLENGE_TTL_SECONDS = 1800

# ── Audit event kinds ────────────────────────────────────────────────────────
AUDIT_JOB_CREATED = "JOB_CREATED"
AUDIT_PHASE_TRANSITION = "PHASE_TRANSITION"
AUDIT_REVIEW_RECORDED = "REVIEW_RECORDED"
AUDIT_REVIEW_INCOMPLETE = "REVIEW_INCOMPLETE"
AUDIT_VERIFICATION_RECORDED = "VERIFICATION_RECORDED"
AUDIT_VERIFICATION_BLOCKED = "VERIFICATION_BLOCKED"
AUDIT_CHALLENGE_ISSUED = "CHALLENGE_ISSUED"
AUDIT_CHALLENGE_CONSUMED = "CHALLENGE_CONSUMED"
AUDIT_CHALLENGE_REVOKED = "CHALLENGE_REVOKED"
AUDIT_VALIDATION_RECEIPT_RECORDED = "VALIDATION_RECEIPT_RECORDED"
AUDIT_REVIEW_RECEIPT_RECORDED = "REVIEW_RECEIPT_RECORDED"
AUDIT_OPERATION_MIGRATED = "OPERATION_MIGRATED"

_TERMINAL_EVENT_KINDS = frozenset({"JOB_FAILED", "JOB_COMPLETED"})

_SHA_RE = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
_HEX64_RE = r"^[0-9a-f]{64}$"

# Exact column layout of the immediately prior (1.0.0) review-orchestrator
# schema.  A metadata-free database is only accepted as the prior schema when
# its tables and columns match this layout exactly; any ambiguity fails closed.
_PRIOR_1_0_0_LAYOUT: dict[str, frozenset[str]] = {
    "review_jobs": frozenset(
        {
            "job_id",
            "request_sha256",
            "owner_principal",
            "phase",
            "status",
            "revision",
            "created_at",
            "updated_at",
            "record_json",
            "record_sha256",
        }
    ),
    "review_audit": frozenset(
        {
            "sequence",
            "event_id",
            "job_id",
            "kind",
            "payload_json",
            "created_at",
            "previous_hash",
            "event_hash",
        }
    ),
    "review_challenges": frozenset(
        {
            "challenge_id",
            "job_id",
            "kind",
            "principal",
            "nonce",
            "issued_at",
            "expires_at",
            "status",
            "consumed_at",
            "consumed_op_id",
            "challenge_json",
            "challenge_sha256",
        }
    ),
    "review_operations": frozenset(
        {
            "op_id",
            "job_id",
            "kind",
            "payload_sha256",
            "result_json",
            "revision",
            "created_at",
        }
    ),
    "review_validation_receipts": frozenset(
        {
            "receipt_id",
            "job_id",
            "snapshot_sha",
            "receipt_json",
            "receipt_sha256",
            "created_at",
        }
    ),
}

AUDIT_JOB_MIGRATED = "JOB_MIGRATED"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_plus(seconds: int) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("job_id must be a UUID") from exc
    if str(parsed) != value:
        raise ValueError("job_id must use canonical UUID text")
    return value


def _validate_relative_path(value: str) -> str:
    if (
        not value
        or value.startswith(("/", "\\"))
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("path must be a relative repository path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("path must not contain empty or traversal components")
    return value


# ── Models ───────────────────────────────────────────────────────────────────
class ReviewJobCreate(StrictModel):
    """Untrusted create intent for a review-orchestration job."""

    job_id: str
    repository_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,63}$")
    worktree_path: str = Field(min_length=2)
    branch: str = Field(min_length=1, max_length=255)
    starting_sha: str = Field(pattern=_SHA_RE)
    current_head: str | None = Field(default=None, pattern=_SHA_RE)
    allowed_paths: list[str] = Field(min_length=1)
    architecture_anchors: list[str] = Field(default_factory=list)
    acceptance_anchors: list[str] = Field(default_factory=list)
    delegation_id: str | None = None

    @field_validator("job_id")
    @classmethod
    def _job_id(cls, value: str) -> str:
        return _validate_uuid(value)

    @field_validator("worktree_path")
    @classmethod
    def _worktree(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("worktree_path must not contain NUL")
        if not value.startswith("/"):
            raise ValueError("worktree_path must be absolute")
        if any(part in {"", ".", ".."} for part in Path(value).parts):
            raise ValueError("worktree_path must be canonical (no traversal)")
        return value

    @field_validator("branch")
    @classmethod
    def _branch(cls, value: str) -> str:
        if value in {"HEAD", "-"}:
            raise ValueError("detached or option-like branch forbidden")
        if "\x00" in value:
            raise ValueError("branch must not contain NUL")
        return value

    @field_validator("allowed_paths", "architecture_anchors", "acceptance_anchors")
    @classmethod
    def _relative_paths(cls, value: list[str]) -> list[str]:
        return [_validate_relative_path(item) for item in value]


class Finding(StrictModel):
    severity: Literal["BLOCKER", "MAJOR", "MINOR"]
    title: str = Field(min_length=1, max_length=200)
    path: str = ""
    detail: str = ""
    raised_by: Literal["codex_mcp", "hermes"] = "codex_mcp"


class TestResult(StrictModel):
    scope: Literal["focused", "full"]
    status: Literal["PASSED", "FAILED", "UNKNOWN"]
    command: str = Field(min_length=1, max_length=2048)
    summary: str = Field(default="", max_length=8192)
    evidence_sha256: str | None = Field(default=None, pattern=_HEX64_RE)
    ran_at: str = Field(min_length=20, max_length=27)

    @field_validator("command", "summary", mode="before")
    @classmethod
    def _redact_persisted_text(cls, value):
        return redact_secrets(value) if isinstance(value, str) else value

    @field_validator("ran_at")
    @classmethod
    def _canonical_utc_timestamp(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("ran_at must be canonical UTC ISO-8601")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ValueError("ran_at must be canonical UTC ISO-8601") from exc
        if parsed.tzinfo != timezone.utc or parsed.isoformat().replace("+00:00", "Z") != value:
            raise ValueError("ran_at must be canonical UTC ISO-8601")
        return value


class ReviewRecordRequest(StrictModel):
    """Opaque review submission: an idempotency key plus a runner-issued
    receipt.  No caller-authored snapshot fields are accepted."""

    op_id: str | None = None
    receipt: dict


class VerificationRecordRequest(StrictModel):
    """Opaque verification submission: an idempotency key, a validator-issued
    receipt, and Hermes' own focused/full test evidence."""

    op_id: str | None = None
    receipt: dict
    focused_test: TestResult
    full_test: TestResult


class TransitionRequest(StrictModel):
    """Hermes-owned phase transition with optimistic concurrency support."""

    target_phase: str
    op_id: str | None = None
    expected_phase: str | None = None
    prompt_sha256: str | None = Field(default=None, pattern=_HEX64_RE)
    delegation_id: str | None = None
    next_action: str | None = Field(default=None, max_length=2048)
    block_reason: str | None = Field(default=None, max_length=2048)

    @field_validator("next_action", "block_reason", mode="before")
    @classmethod
    def _redact_persisted_text(cls, value):
        return redact_secrets(value) if isinstance(value, str) else value


class ReviewJobRecord(StrictModel):
    """The full persisted record. Loaded records must validate or the job is
    treated as corrupt/unsupported and read fails closed."""

    job_id: str
    schema_version: str
    created_at: str
    updated_at: str

    repository_id: str
    worktree_path: str
    branch: str
    starting_sha: str
    baseline_evidence: dict = Field(default_factory=dict)
    current_head: str
    current_diff_hash: str

    phase: str
    status: str
    active_worker: str | None = None
    delegation_id: str | None = None
    review_round: int = 0

    codex_thread_id: str | None = None
    codex_cli_version: str | None = None
    codex_audit: dict = Field(default_factory=dict)

    blocker_count: int = 0
    major_count: int = 0
    minor_count: int = 0
    findings: list[Finding] = Field(default_factory=list)

    last_focused_test: TestResult | None = None
    last_full_test: TestResult | None = None
    verification_evidence: dict = Field(default_factory=dict)

    block_reason: str = ""
    next_action: str = ""
    merge_ready: bool = False

    allowed_paths: list[str]
    architecture_anchors: list[str] = Field(default_factory=list)
    acceptance_anchors: list[str] = Field(default_factory=list)

    blocking_phase: str | None = None
    resume_target: str | None = None
    owner_principal: str

    @field_validator("phase")
    @classmethod
    def _phase(cls, value: str) -> str:
        if value not in PHASES:
            raise ValueError(f"unsupported phase: {value}")
        return value

    @field_validator("status")
    @classmethod
    def _status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"unsupported status: {value}")
        return value

    @field_validator("blocking_phase", "resume_target")
    @classmethod
    def _optional_phase(cls, value: str | None) -> str | None:
        if value is not None and value not in PHASES:
            raise ValueError(f"unsupported phase: {value}")
        return value


# ── Store ────────────────────────────────────────────────────────────────────
class ReviewStore:
    """Durable, hash-checked, tamper-evident store for review-orchestration
    jobs. Follows the ``DispatchStore`` conventions: WAL, an in-process RLock,
    ``BEGIN IMMEDIATE`` transactions, a chained audit journal, a monotonic
    persisted revision for compare-and-swap, single-use challenges (with
    atomic supersession), immutable receipts, and op-id idempotency keyed by
    (principal, job_id, kind, op_id, payload_sha256).

    Every mutation re-verifies the complete record/audit/challenge/receipt
    consistency inside the same ``BEGIN IMMEDIATE`` transaction, closing the
    load-then-mutate TOCTOU gap.  The signed checkpoint provides
    ``local_consistency_and_single_artifact_rollback_detection``.  It detects
    rollback of either the database or anchor alone; coordinated rollback of
    the database, anchor, and signing keys is explicitly outside this local
    threat model.

    Populated legacy stores without a signed anchor are never adopted or
    re-anchored.  Operators must provision a fresh current-schema store and
    perform an explicit cutover after retaining the legacy store as evidence.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        challenge_ttl_seconds: int = CHALLENGE_TTL_SECONDS,
        authority: ReceiptAuthority | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.anchor_path = Path(f"{self.path}.audit-anchor.json")
        self.pending_anchor_path = Path(f"{self.path}.audit-anchor.pending.json")
        self.lock_path = Path(f"{self.path}.audit-anchor.lock")
        self._database_preexisted = self.path.exists()
        self._lock = threading.RLock()
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.authority = authority
        self._verify_storage_paths(include_missing=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self._verify_storage_paths(include_missing=True)
        previous_umask = os.umask(0o077)
        try:
            if not self.path.exists():
                descriptor = os.open(
                    self.path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                os.close(descriptor)
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
        finally:
            os.umask(previous_umask)
        self._verify_storage_paths(include_missing=False)
        return conn

    @contextmanager
    def _exclusive_store_lock(self):
        """Serialize DB mutation and anchor publication across processes."""
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()  # windows-footgun: ok -- Unix owner check
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise AdapterError("STORE_PATH_INVALID", "unsafe review store lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @contextmanager
    def _locked_connection(self):
        """Open a connection only after crash recovery and anchor verification."""
        with self._lock, self._exclusive_store_lock(), self._connect() as conn:
            self._reconcile_pending(conn)
            if self.authority is not None:
                self._verify_anchor(conn)
            yield conn

    def attach_authority(self, authority: ReceiptAuthority | None) -> None:
        """Attach checkpoint authority only to this instance's untouched store.

        Some embedders construct the store immediately before constructing the
        orchestrator.  That remains safe only while the database is provably a
        brand-new empty initialization created by this object; an existing or
        used database can never gain a replacement anchor this way.
        """
        if authority is None or self.authority is authority:
            return
        if self.authority is not None:
            raise AdapterError("AUDIT_ROLLBACK", "review store authority changed")
        with self._lock, self._exclusive_store_lock(), self._connect() as conn:
            if (
                self._database_preexisted
                or self._read_anchor() is not None
                or self._read_pending() is not None
                or conn.execute("SELECT 1 FROM review_jobs LIMIT 1").fetchone()
                or conn.execute("SELECT 1 FROM review_audit LIMIT 1").fetchone()
            ):
                raise AdapterError(
                    "AUDIT_ROLLBACK",
                    "authority cannot attach to an initialized or nonempty store",
                )
            self.authority = authority
            try:
                self._append_anchor(self._new_anchor(conn, None))
            except Exception:
                self.authority = None
                raise

    def _verify_storage_paths(self, *, include_missing: bool) -> None:
        try:
            parent = self.path.parent.lstat()
        except OSError as exc:
            raise AdapterError("STORE_PATH_INVALID", "review store parent is inaccessible") from exc
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()  # windows-footgun: ok -- Unix owner check
            or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise AdapterError(
                "STORE_PATH_INVALID", "owner-only review store directory required"
            )
        candidates = (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            self.anchor_path,
            self.pending_anchor_path,
            self.lock_path,
        )
        for candidate in candidates:
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                if include_missing:
                    continue
                if candidate == self.path:
                    raise AdapterError("STORE_PATH_INVALID", "review database disappeared")
                continue
            except OSError as exc:
                raise AdapterError("STORE_PATH_INVALID", "review store path is inaccessible") from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()  # windows-footgun: ok -- Unix owner check
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise AdapterError(
                    "STORE_PATH_INVALID", "unsafe review database or anchor path"
                )

    @staticmethod
    def _security_tables() -> tuple[str, ...]:
        return (
            "review_meta",
            "review_jobs",
            "review_audit",
            "review_challenges",
            "review_operations",
            "review_runner_receipts",
            "review_validation_receipts",
        )

    @staticmethod
    def _schema_definitions(conn: sqlite3.Connection) -> list[dict]:
        """Return canonical application-owned table/index/trigger definitions."""
        rows = conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE type IN ('table','index','trigger') "
            "AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type,name,tbl_name,sql"
        ).fetchall()
        return [
            {
                "type": row["type"],
                "name": row["name"],
                "tbl_name": row["tbl_name"],
                "sql": row["sql"],
            }
            for row in rows
        ]

    @classmethod
    def _schema_layout(cls, conn: sqlite3.Connection) -> dict:
        """Return migration-stable structural schema material."""
        definitions = cls._schema_definitions(conn)
        tables = sorted(
            definition["name"]
            for definition in definitions
            if definition["type"] == "table"
        )
        indexes = sorted(
            definition["name"]
            for definition in definitions
            if definition["type"] == "index"
        )
        return {
            "objects": [
                {
                    "type": definition["type"],
                    "name": definition["name"],
                    "tbl_name": definition["tbl_name"],
                }
                for definition in definitions
            ],
            "columns": {
                table: sorted(
                    (
                        {
                            "name": row["name"],
                            "type": row["type"],
                            "notnull": row["notnull"],
                            "default": row["dflt_value"],
                            "pk": row["pk"],
                        }
                        for row in conn.execute(f'PRAGMA table_info("{table}")')
                    ),
                    key=lambda column: column["name"],
                )
                for table in tables
            },
            "indexes": {
                index: [
                    {"sequence": row["seqno"], "column": row["name"]}
                    for row in conn.execute(f'PRAGMA index_info("{index}")')
                ]
                for index in indexes
            },
        }

    def _validate_current_schema_layout(self, conn: sqlite3.Connection) -> None:
        """Require the exact current application schema, including triggers."""
        reference = sqlite3.connect(":memory:", isolation_level=None)
        reference.row_factory = sqlite3.Row
        try:
            reference.execute("BEGIN IMMEDIATE")
            self._create_schema(reference, fault_injection=False)
            expected = self._schema_layout(reference)
            reference.rollback()
        finally:
            reference.close()
        if self._schema_layout(conn) != expected:
            raise AdapterError(
                "UNSUPPORTED_SCHEMA", "review store current schema layout is invalid"
            )

    def _state_checkpoint_body(
        self,
        conn: sqlite3.Connection,
        generation: int,
        *,
        previous_anchor_sha256: str | None = None,
    ) -> dict:
        tables: dict[str, list[dict]] = {}
        for table in self._security_tables():
            columns = [
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            ]
            order = ",".join(f'"{column}"' for column in columns)
            rows = conn.execute(
                f'SELECT * FROM "{table}" ORDER BY {order}'
            ).fetchall()
            tables[table] = [
                {column: row[column] for column in columns} for row in rows
            ]
        head = conn.execute(
            "SELECT sequence,event_hash FROM review_audit "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        state = {
            "schema": self._schema_definitions(conn),
            "tables": tables,
        }
        body = {
            "checkpoint_kind": "review-store-state-v1",
            "generation": generation,
            "state_sha256": sha256_bytes(canonical_json_bytes(state)),
            "audit_head": (
                {"sequence": head["sequence"], "event_hash": head["event_hash"]}
                if head is not None
                else None
            ),
        }
        if previous_anchor_sha256 is not None:
            body["previous_anchor_sha256"] = previous_anchor_sha256
        return body

    @staticmethod
    def _anchor_body(anchor: dict) -> dict:
        keys = ("checkpoint_kind", "generation", "state_sha256", "audit_head")
        body = {key: anchor.get(key) for key in keys}
        if "previous_anchor_sha256" in anchor:
            body["previous_anchor_sha256"] = anchor.get("previous_anchor_sha256")
        return body

    @staticmethod
    def _anchor_sha256(anchor: dict) -> str:
        return sha256_bytes(canonical_json_bytes(anchor))

    def _read_json_file(self, path: Path, *, limit: int = 1_000_000) -> bytes | None:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AdapterError("AUDIT_ROLLBACK", "audit proof is inaccessible") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()  # windows-footgun: ok -- Unix owner check
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > limit
            ):
                raise AdapterError("AUDIT_ROLLBACK", "audit proof is unsafe")
            return os.read(descriptor, limit + 1)
        finally:
            os.close(descriptor)

    def _read_anchors(self) -> Sequence[dict]:
        raw = self._read_json_file(self.anchor_path, limit=10_000_000)
        if raw is None:
            return []
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdapterError("AUDIT_ROLLBACK", "audit anchor is invalid") from exc
        if not records or not all(isinstance(record, dict) for record in records):
            raise AdapterError("AUDIT_ROLLBACK", "audit anchor is invalid")
        return records

    def _read_anchor(self) -> dict | None:
        anchors = self._read_anchors()
        return anchors[-1] if anchors else None

    def _verify_anchor_chain(self) -> Sequence[dict]:
        anchors = self._read_anchors()
        if self.authority is None:
            return anchors
        previous: dict | None = None
        for anchor in anchors:
            body = self._anchor_body(anchor)
            try:
                self.authority.verify_capsule_checkpoint(body, anchor)
            except AdapterError as exc:
                raise AdapterError("AUDIT_ROLLBACK", "audit anchor proof is invalid") from exc
            generation = body["generation"]
            if not isinstance(generation, int) or generation < 0:
                raise AdapterError("AUDIT_ROLLBACK", "audit anchor generation is invalid")
            if previous is None:
                # A one-record file is the bounded, atomic latest-checkpoint
                # representation.  Multi-record legacy files still receive
                # complete chain validation until the next mutation compacts
                # them to the latest signed checkpoint.
                if len(anchors) > 1 and (
                    generation != 0 or body.get("previous_anchor_sha256") is not None
                ):
                    raise AdapterError("AUDIT_ROLLBACK", "audit anchor history is truncated")
            elif (
                generation != int(previous["generation"]) + 1
                or body.get("previous_anchor_sha256") != self._anchor_sha256(previous)
            ):
                raise AdapterError("AUDIT_ROLLBACK", "audit anchor history is not monotonic")
            previous = anchor
        return anchors

    def _verify_anchor(self, conn: sqlite3.Connection) -> None:
        if self.authority is None:
            return
        anchors = self._verify_anchor_chain()
        anchor = anchors[-1] if anchors else None
        if anchor is None:
            raise AdapterError("AUDIT_ROLLBACK", "required audit anchor is missing")
        body = self._anchor_body(anchor)
        expected = self._state_checkpoint_body(
            conn,
            body["generation"],
            previous_anchor_sha256=body.get("previous_anchor_sha256"),
        )
        if body != expected:
            raise AdapterError(
                "AUDIT_ROLLBACK", "database state or audit head rolled back"
            )

    def _fsync_directory(self) -> None:
        directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _write_json_atomic(self, path: Path, value: dict) -> None:
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            payload = canonical_json_bytes(value)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        self._fsync_directory()

    def _append_anchor(self, anchor: dict) -> None:
        existing = self._read_anchors()
        if existing:
            previous = existing[-1]
            body = self._anchor_body(anchor)
            if (
                body.get("generation") != int(previous["generation"]) + 1
                or body.get("previous_anchor_sha256") != self._anchor_sha256(previous)
            ):
                raise AdapterError("AUDIT_ROLLBACK", "refusing non-monotonic audit anchor")
        elif self._anchor_body(anchor).get("generation") != 0:
            raise AdapterError("AUDIT_ROLLBACK", "refusing truncated audit anchor")
        # Keep one bounded signed checkpoint.  Temp-file publication means a
        # crash yields either the old or new complete record, never a torn
        # append, while the signed pending intent reconciles the DB commit.
        self._write_json_atomic(self.anchor_path, anchor)
        self._verify_storage_paths(include_missing=False)

    def _read_pending(self) -> dict | None:
        raw = self._read_json_file(self.pending_anchor_path)
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdapterError("AUDIT_ROLLBACK", "pending anchor intent is invalid") from exc
        if not isinstance(value, dict):
            raise AdapterError("AUDIT_ROLLBACK", "pending anchor intent is invalid")
        return value

    def _remove_pending(self) -> None:
        try:
            self.pending_anchor_path.unlink()
        except FileNotFoundError:
            return
        self._fsync_directory()

    def _fault_inject(self, point: str) -> None:
        """Test seam for simulating process loss at durability boundaries."""

    def _new_anchor(self, conn: sqlite3.Connection, current: dict | None) -> dict:
        authority = self.authority
        if authority is None:
            raise AdapterError("AUDIT_ROLLBACK", "checkpoint authority is unavailable")
        generation = int(current["generation"]) + 1 if current is not None else 0
        previous = self._anchor_sha256(current) if current is not None else None
        body = self._state_checkpoint_body(
            conn, generation, previous_anchor_sha256=previous
        )
        return {**body, **authority.sign_capsule_checkpoint(body)}

    def _commit_with_anchor(
        self, conn: sqlite3.Connection, *, allow_initial: bool = False
    ) -> None:
        if self.authority is None:
            conn.commit()
            return
        current = self._read_anchor()
        if current is None and not allow_initial:
            raise AdapterError("AUDIT_ROLLBACK", "required audit anchor is missing")
        if current is not None:
            self._verify_anchor_chain()
        target = self._new_anchor(conn, current)
        intent_body = {
            "checkpoint_kind": "review-store-anchor-intent-v1",
            "base_anchor_sha256": (
                self._anchor_sha256(current) if current is not None else None
            ),
            "base_anchor": current,
            "base_checkpoint": self._anchor_body(current) if current is not None else None,
            "target_anchor": target,
        }
        intent = {**intent_body, **self.authority.sign_capsule_checkpoint(intent_body)}
        existing_pending = self._read_pending()
        if existing_pending is not None:
            pending_kind = existing_pending.get("checkpoint_kind")
            if not (allow_initial and pending_kind == "review-store-schema-intent-v1"):
                raise AdapterError("AUDIT_ROLLBACK", "unreconciled anchor intent exists")
        self._write_json_atomic(self.pending_anchor_path, intent)
        self._fault_inject("after_intent_before_commit")
        conn.commit()
        for candidate in (self.path, Path(f"{self.path}-wal")):
            try:
                descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                continue
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        self._fault_inject("after_commit_before_finalize")
        self._append_anchor(target)
        self._remove_pending()

    def _reconcile_pending(self, conn: sqlite3.Connection) -> None:
        if self.authority is None:
            return
        pending = self._read_pending()
        if pending is None:
            return
        if pending.get("checkpoint_kind") == "review-store-schema-intent-v1":
            body = {
                "checkpoint_kind": pending.get("checkpoint_kind"),
                "schema_version": pending.get("schema_version"),
            }
            try:
                self.authority.verify_capsule_checkpoint(body, pending)
            except AdapterError as exc:
                raise AdapterError("AUDIT_ROLLBACK", "schema intent is invalid") from exc
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if body["schema_version"] != SCHEMA_VERSION or tables:
                raise AdapterError("AUDIT_ROLLBACK", "schema intent cannot reconcile store")
            return
        body = {
            key: pending.get(key)
            for key in (
                "checkpoint_kind",
                "base_anchor_sha256",
                "base_anchor",
                "base_checkpoint",
                "target_anchor",
            )
        }
        try:
            self.authority.verify_capsule_checkpoint(body, pending)
        except AdapterError as exc:
            raise AdapterError("AUDIT_ROLLBACK", "pending anchor intent is invalid") from exc
        if body["checkpoint_kind"] != "review-store-anchor-intent-v1" or not isinstance(
            body["target_anchor"], dict
        ):
            raise AdapterError("AUDIT_ROLLBACK", "pending anchor intent is invalid")
        target_anchor = body["target_anchor"]
        target = self._anchor_body(target_anchor)
        try:
            self.authority.verify_capsule_checkpoint(target, target_anchor)
        except AdapterError as exc:
            raise AdapterError("AUDIT_ROLLBACK", "pending target anchor is invalid") from exc
        base_anchor = body["base_anchor"]
        base = body["base_checkpoint"]
        if base_anchor is not None:
            if not isinstance(base_anchor, dict) or self._anchor_body(base_anchor) != base:
                raise AdapterError("AUDIT_ROLLBACK", "pending base anchor is invalid")
            try:
                self.authority.verify_capsule_checkpoint(base, base_anchor)
            except AdapterError as exc:
                raise AdapterError("AUDIT_ROLLBACK", "pending base anchor is invalid") from exc
            if self._anchor_sha256(base_anchor) != body["base_anchor_sha256"]:
                raise AdapterError("AUDIT_ROLLBACK", "pending base anchor hash is invalid")
        try:
            anchors = self._verify_anchor_chain()
            current = anchors[-1] if anchors else None
        except AdapterError:
            # A process may die during a legacy append or an external write may
            # tear the anchor.  Only the signed intent plus an exact base/target
            # DB digest may repair it below.
            current = None
        current_sha = self._anchor_sha256(current) if current is not None else None
        if current_sha != body["base_anchor_sha256"]:
            target_sha = self._anchor_sha256(target_anchor)
            if current_sha == target_sha:
                self._verify_anchor(conn)
                self._remove_pending()
                return
            if current is not None:
                raise AdapterError("AUDIT_ROLLBACK", "pending anchor base does not match history")
        if base is None:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if not tables:
                # Initial schema transaction never committed.  Preserve a
                # signed recovery marker so reopening can safely retry rather
                # than misclassifying the crash-created empty DB as legacy.
                schema_intent_body = {
                    "checkpoint_kind": "review-store-schema-intent-v1",
                    "schema_version": SCHEMA_VERSION,
                }
                self._write_json_atomic(
                    self.pending_anchor_path,
                    {
                        **schema_intent_body,
                        **self.authority.sign_capsule_checkpoint(schema_intent_body),
                    },
                )
                return
        if base is not None:
            actual_base = self._state_checkpoint_body(
                conn,
                base["generation"],
                previous_anchor_sha256=base.get("previous_anchor_sha256"),
            )
            if actual_base == base:
                if base_anchor is None:
                    raise AdapterError("AUDIT_ROLLBACK", "pending base anchor is unavailable")
                self._write_json_atomic(self.anchor_path, base_anchor)
                self._remove_pending()
                return
        actual_target = self._state_checkpoint_body(
            conn,
            target["generation"],
            previous_anchor_sha256=target.get("previous_anchor_sha256"),
        )
        if actual_target == target:
            # The signed intent binds the exact target record. Verify its inner
            # signature before publishing it to the append-only history.
            self._write_json_atomic(self.anchor_path, target_anchor)
            self._remove_pending()
            return
        raise AdapterError("AUDIT_ROLLBACK", "pending anchor cannot reconcile database state")

    # -- schema (versioned, transactional) -----------------------------------
    def _initialize(self) -> None:
        with self._lock, self._exclusive_store_lock(), self._connect() as conn:
            initial_tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self._reconcile_pending(conn)
            pending = self._read_pending()
            schema_recovery = (
                pending is not None
                and pending.get("checkpoint_kind") == "review-store-schema-intent-v1"
            )
            if self.authority is not None and self._read_anchor() is None:
                if (self._database_preexisted or initial_tables) and not schema_recovery:
                    raise AdapterError(
                        "AUDIT_ROLLBACK",
                        "initialized review store is missing its required audit anchor",
                    )
            if initial_tables and self.authority is not None:
                # Authenticate the exact pre-migration database first.  A
                # rolled-back or relabelled schema must never be interpreted as
                # legitimate legacy input before its checkpoint is checked.
                self._verify_anchor(conn)
            if self.authority is not None and not initial_tables and not schema_recovery:
                schema_intent_body = {
                    "checkpoint_kind": "review-store-schema-intent-v1",
                    "schema_version": SCHEMA_VERSION,
                }
                self._write_json_atomic(
                    self.pending_anchor_path,
                    {
                        **schema_intent_body,
                        **self.authority.sign_capsule_checkpoint(schema_intent_body),
                    },
                )
                self._fault_inject("after_schema_intent")
            conn.execute("BEGIN IMMEDIATE")
            try:
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if "review_meta" in tables:
                    meta = conn.execute(
                        "SELECT value FROM review_meta WHERE key='schema_version'"
                    ).fetchone()
                    if meta is not None and meta["value"] == PREVIOUS_SCHEMA_VERSION:
                        self._migrate_from_1_2(conn)
                    elif meta is not None and meta["value"] == OPERATION_SCHEMA_VERSION:
                        self._migrate_from_1_1(conn)
                    elif meta is None or meta["value"] != SCHEMA_VERSION:
                        conn.rollback()
                        raise AdapterError(
                            "UNSUPPORTED_SCHEMA",
                            "review store schema version is unsupported "
                            f"(found {meta['value'] if meta else 'unknown'}, "
                            f"expected {SCHEMA_VERSION})",
                        )
                elif "review_jobs" in tables:
                    self._migrate_from_prior(conn)
                else:
                    self._create_schema(conn)
                # The signed production store is fresh-cutover only and must
                # have the exact hardened layout.  Authority-free stores retain
                # legacy migration compatibility for tests/offline tooling;
                # they do not claim signed checkpoint protection.
                if self.authority is not None:
                    self._validate_current_schema_layout(conn)
                self._verify_audit_chain_on(conn)
                for row in conn.execute("SELECT job_id FROM review_jobs").fetchall():
                    self._verify_job_integrity_on(conn, row["job_id"])
                self._commit_with_anchor(conn, allow_initial=not initial_tables)
            except AdapterError:
                conn.rollback()
                raise
            except Exception as exc:
                conn.rollback()
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "review store schema initialization failed"
                ) from exc
        self.path.chmod(0o600)

    def _create_schema(
        self, conn: sqlite3.Connection, *, fault_injection: bool = True
    ) -> None:
        self._execute_schema_script(
            conn,
            """
            CREATE TABLE review_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO review_meta(key, value) VALUES ('schema_version', '{version}');
            CREATE TABLE review_jobs (
                job_id TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL,
                owner_principal TEXT NOT NULL,
                phase TEXT NOT NULL,
                status TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                record_json TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                CHECK(length(request_sha256) = 64),
                CHECK(length(record_sha256) = 64)
            );
            CREATE INDEX review_jobs_phase ON review_jobs(phase);
            CREATE INDEX review_jobs_status ON review_jobs(status);
            CREATE TABLE review_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                job_id TEXT,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            CREATE TABLE review_challenges (
                challenge_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                principal TEXT NOT NULL,
                round INTEGER NOT NULL DEFAULT 0,
                nonce TEXT NOT NULL,
                prompt_sha256 TEXT,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                consumed_at TEXT,
                consumed_op_id TEXT,
                revoked_at TEXT,
                superseded_by TEXT,
                challenge_json TEXT NOT NULL,
                challenge_sha256 TEXT NOT NULL,
                CHECK(length(challenge_sha256) = 64)
            );
            CREATE INDEX review_challenges_job
                ON review_challenges(job_id, kind, status);
            CREATE TABLE review_operations (
                op_id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                job_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                operation_sha256 TEXT NOT NULL,
                CHECK(length(payload_sha256) = 64),
                CHECK(length(result_sha256) = 64),
                CHECK(length(operation_sha256) = 64)
            );
            CREATE TABLE review_runner_receipts (
                receipt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signing_algorithm TEXT NOT NULL,
                proof TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                CHECK(length(receipt_sha256) = 64)
            );
            CREATE INDEX review_runner_receipts_job
                ON review_runner_receipts(job_id, challenge_id);
            CREATE TABLE review_validation_receipts (
                receipt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                snapshot_sha TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signing_algorithm TEXT NOT NULL,
                proof TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                CHECK(length(receipt_sha256) = 64)
            );
            CREATE INDEX review_validation_receipts_job
                ON review_validation_receipts(job_id, snapshot_sha);
            CREATE TRIGGER review_jobs_identity_immutable
            BEFORE UPDATE OF request_sha256 ON review_jobs
            WHEN NEW.request_sha256 != OLD.request_sha256
            BEGIN
                SELECT RAISE(ABORT, 'review job identity is immutable');
            END;
            CREATE TRIGGER review_jobs_owner_immutable
            BEFORE UPDATE OF owner_principal ON review_jobs
            WHEN NEW.owner_principal != OLD.owner_principal
            BEGIN
                SELECT RAISE(ABORT, 'review job owner is immutable');
            END;
            CREATE TRIGGER review_runner_receipts_immutable_update
            BEFORE UPDATE ON review_runner_receipts
            BEGIN
                SELECT RAISE(ABORT, 'review runner receipt is immutable');
            END;
            CREATE TRIGGER review_runner_receipts_immutable_delete
            BEFORE DELETE ON review_runner_receipts
            BEGIN
                SELECT RAISE(ABORT, 'review runner receipt is immutable');
            END;
            CREATE TRIGGER review_validation_receipts_immutable_update
            BEFORE UPDATE ON review_validation_receipts
            BEGIN
                SELECT RAISE(ABORT, 'validation receipt is immutable');
            END;
            CREATE TRIGGER review_validation_receipts_immutable_delete
            BEFORE DELETE ON review_validation_receipts
            BEGIN
                SELECT RAISE(ABORT, 'validation receipt is immutable');
            END;
            """.replace("{version}", SCHEMA_VERSION),
            fault_injection=fault_injection,
        )

    def _execute_schema_script(
        self,
        conn: sqlite3.Connection,
        script: str,
        *,
        fault_injection: bool = True,
    ) -> None:
        """Execute DDL without sqlite3 ``executescript``'s implicit COMMIT."""
        statement = ""
        index = 0
        for line in script.splitlines(keepends=True):
            statement += line
            if not sqlite3.complete_statement(statement):
                continue
            if statement.strip():
                conn.execute(statement)
                if fault_injection:
                    self._fault_inject(f"after_schema_statement:{index}")
                index += 1
            statement = ""
        if statement.strip():
            raise AdapterError("UNSUPPORTED_SCHEMA", "incomplete review store schema")

    def _migrate_from_prior(self, conn: sqlite3.Connection) -> None:
        """Migrate the immediately prior (1.0.0) review-orchestrator schema.

        The prior schema had the same five tables but no ``review_meta``, no
        ``round``/``prompt_sha256``/``revoked_at``/``superseded_by`` challenge
        columns, no ``principal`` on operations, and no runner-receipt table.

        The migration is transactional (it runs inside the caller's
        ``BEGIN IMMEDIATE``) and fails closed: the exact 1.0.0 layout is
        validated first, the pre-migration integrity is verified, every record
        is transformed to the current model with a recomputed hash, legacy
        validation receipts are rebound to their challenge (never excluded from
        verification), and the whole store is re-verified before the schema
        version is stamped.  Any failure rolls back with no partial stamping.
        """
        self._validate_prior_layout(conn)
        self._verify_prior_integrity(conn)
        for row in conn.execute("SELECT job_id,record_json FROM review_jobs"):
            try:
                record = json.loads(row["record_json"])
            except ValueError as exc:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "prior review job record is unparseable"
                ) from exc
            if not isinstance(record, dict) or record.get("schema_version") != PRIOR_SCHEMA_VERSION:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior review job {row['job_id']} has an unsupported schema version",
                )
        if conn.execute(
            "SELECT count(*) AS count FROM review_validation_receipts"
        ).fetchone()["count"]:
            raise AdapterError(
                "LEGACY_RECEIPT_KEY_REQUIRED",
                "legacy receipts require explicitly configured legacy signing keys",
            )
        self._apply_prior_schema_ddl(conn)
        self._transform_prior_records(conn)
        self._migrate_prior_receipts(conn)
        self._migrate_operation_results(conn)
        self._bind_unhashed_operations(conn)
        # Post-migration: the store must already be fully integrity-covered.
        self._verify_audit_chain_on(conn)
        for row in conn.execute("SELECT job_id FROM review_jobs").fetchall():
            self._verify_job_integrity_on(conn, row["job_id"])

    def _validate_prior_layout(self, conn: sqlite3.Connection) -> None:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != set(_PRIOR_1_0_0_LAYOUT):
            raise AdapterError(
                "UNSUPPORTED_SCHEMA",
                "review store layout is not the recognized 1.0.0 schema",
            )
        for table, expected in _PRIOR_1_0_0_LAYOUT.items():
            columns = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if columns != expected:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"review store table {table} has an unrecognized layout",
                )

    def _verify_prior_integrity(self, conn: sqlite3.Connection) -> None:
        self._verify_audit_chain_on(conn)
        for row in conn.execute(
            "SELECT record_json, record_sha256 FROM review_jobs"
        ):
            if sha256_bytes(row["record_json"].encode("utf-8")) != row["record_sha256"]:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "prior review job record is corrupted"
                )
        for row in conn.execute(
            "SELECT challenge_json, challenge_sha256 FROM review_challenges"
        ):
            if sha256_bytes(row["challenge_json"].encode("utf-8")) != row["challenge_sha256"]:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "prior review challenge is corrupted"
                )
        for row in conn.execute(
            "SELECT receipt_json, receipt_sha256 FROM review_validation_receipts"
        ):
            if sha256_bytes(row["receipt_json"].encode("utf-8")) != row["receipt_sha256"]:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "prior review receipt is corrupted"
                )

    def _apply_prior_schema_ddl(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "ALTER TABLE review_challenges ADD COLUMN round INTEGER NOT NULL DEFAULT 0"
        )
        conn.execute(
            "ALTER TABLE review_challenges ADD COLUMN prompt_sha256 TEXT"
        )
        conn.execute("ALTER TABLE review_challenges ADD COLUMN revoked_at TEXT")
        conn.execute("ALTER TABLE review_challenges ADD COLUMN superseded_by TEXT")
        conn.execute(
            "ALTER TABLE review_operations "
            "ADD COLUMN principal TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "UPDATE review_operations SET principal=("
            "SELECT owner_principal FROM review_jobs "
            "WHERE review_jobs.job_id=review_operations.job_id)"
        )
        conn.execute("ALTER TABLE review_operations ADD COLUMN result_sha256 TEXT")
        conn.execute("ALTER TABLE review_operations ADD COLUMN operation_sha256 TEXT")
        conn.execute("ALTER TABLE review_validation_receipts ADD COLUMN challenge_id TEXT")
        conn.execute(
            "ALTER TABLE review_validation_receipts ADD COLUMN signing_key_id TEXT NOT NULL"
        )
        conn.execute(
            "ALTER TABLE review_validation_receipts ADD COLUMN signing_algorithm TEXT NOT NULL"
        )
        conn.execute(
            "ALTER TABLE review_validation_receipts ADD COLUMN proof TEXT NOT NULL"
        )
        conn.execute("CREATE TABLE review_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "INSERT INTO review_meta(key, value) VALUES ('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        conn.execute(
            """
            CREATE TABLE review_runner_receipts (
                receipt_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                challenge_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                signing_algorithm TEXT NOT NULL,
                proof TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                CHECK(length(receipt_sha256) = 64)
            )
            """
        )
        conn.execute(
            "CREATE INDEX review_runner_receipts_job "
            "ON review_runner_receipts(job_id, challenge_id)"
        )
        conn.execute(
            "CREATE TRIGGER review_runner_receipts_immutable_update "
            "BEFORE UPDATE ON review_runner_receipts "
            "BEGIN SELECT RAISE(ABORT, 'review runner receipt is immutable'); END"
        )
        conn.execute(
            "CREATE TRIGGER review_runner_receipts_immutable_delete "
            "BEFORE DELETE ON review_runner_receipts "
            "BEGIN SELECT RAISE(ABORT, 'review runner receipt is immutable'); END"
        )

    @staticmethod
    def _add_receipt_metadata_columns(conn: sqlite3.Connection) -> None:
        receipt_count = conn.execute(
            "SELECT (SELECT count(*) FROM review_runner_receipts) + "
            "(SELECT count(*) FROM review_validation_receipts) AS count"
        ).fetchone()["count"]
        if receipt_count:
            raise AdapterError(
                "LEGACY_RECEIPT_KEY_REQUIRED",
                "legacy receipts require explicitly configured legacy signing keys",
            )
        for table in ("review_runner_receipts", "review_validation_receipts"):
            columns = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            metadata = {"signing_key_id", "signing_algorithm", "proof"}
            present = columns & metadata
            if present == metadata:
                continue
            if present:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "receipt proof metadata layout is partial"
                )
            conn.execute(f"ALTER TABLE {table} ADD COLUMN signing_key_id TEXT NOT NULL")
            conn.execute(f"ALTER TABLE {table} ADD COLUMN signing_algorithm TEXT NOT NULL")
            conn.execute(f"ALTER TABLE {table} ADD COLUMN proof TEXT NOT NULL")

    def _migrate_from_1_2(self, conn: sqlite3.Connection) -> None:
        """Add immutable proof metadata; never relabel unverifiable receipts."""
        self._add_receipt_metadata_columns(conn)
        self._transform_prior_records(conn, from_schema=PREVIOUS_SCHEMA_VERSION)
        conn.execute(
            "UPDATE review_meta SET value=? WHERE key='schema_version'",
            (SCHEMA_VERSION,),
        )

    def _migrate_from_1_1(self, conn: sqlite3.Connection) -> None:
        """Transactionally bind legacy 1.1 operation rows to their results."""
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(review_operations)")
        }
        expected = {
            "op_id",
            "principal",
            "job_id",
            "kind",
            "payload_sha256",
            "result_json",
            "revision",
            "created_at",
        }
        if columns != expected:
            raise AdapterError(
                "UNSUPPORTED_SCHEMA", "review operation table has an unrecognized layout"
            )
        self._verify_audit_chain_on(conn)
        for row in conn.execute("SELECT job_id FROM review_jobs").fetchall():
            self._verify_job_integrity_on(conn, row["job_id"], verify_operations=False)
        self._add_receipt_metadata_columns(conn)
        conn.execute("ALTER TABLE review_operations ADD COLUMN result_sha256 TEXT")
        conn.execute("ALTER TABLE review_operations ADD COLUMN operation_sha256 TEXT")
        self._transform_prior_records(conn, from_schema=OPERATION_SCHEMA_VERSION)
        self._migrate_operation_results(conn)
        self._bind_unhashed_operations(conn)
        conn.execute(
            "UPDATE review_meta SET value=? WHERE key='schema_version'",
            (SCHEMA_VERSION,),
        )
        for row in conn.execute("SELECT job_id FROM review_jobs").fetchall():
            self._verify_job_integrity_on(conn, row["job_id"])

    @staticmethod
    def _operation_sha256(
        *,
        op_id: str,
        principal: str,
        job_id: str,
        kind: str,
        payload_sha256: str,
        result_sha256: str,
        revision: int,
        created_at: int,
    ) -> str:
        return canonical_sha256(
            {
                "op_id": op_id,
                "principal": principal,
                "job_id": job_id,
                "kind": kind,
                "payload_sha256": payload_sha256,
                "result_sha256": result_sha256,
                "revision": revision,
                "created_at": created_at,
            }
        )

    def _migrate_operation_results(self, conn: sqlite3.Connection) -> None:
        for row in conn.execute(
            "SELECT op_id, result_json FROM review_operations"
        ).fetchall():
            try:
                result = json.loads(row["result_json"])
            except (TypeError, ValueError) as exc:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "legacy operation result is unparseable"
                ) from exc
            if not isinstance(result, dict):
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "legacy operation result is not an object"
                )
            state = dict(result)
            review_challenge = state.pop("review_challenge", None)
            verification_challenge = state.pop("verification_challenge", None)
            if state.get("schema_version") in {
                PRIOR_SCHEMA_VERSION,
                OPERATION_SCHEMA_VERSION,
                PREVIOUS_SCHEMA_VERSION,
            }:
                state["schema_version"] = SCHEMA_VERSION
                try:
                    state = ReviewJobRecord.model_validate(state).model_dump(mode="json")
                except ValidationError as exc:
                    raise AdapterError(
                        "UNSUPPORTED_SCHEMA",
                        "legacy operation result cannot migrate to the current model",
                    ) from exc
            if review_challenge is not None:
                state["review_challenge"] = review_challenge
            if verification_challenge is not None:
                state["verification_challenge"] = verification_challenge
            conn.execute(
                "UPDATE review_operations SET result_json=? WHERE op_id=?",
                (canonical_json_bytes(state).decode("utf-8"), row["op_id"]),
            )

    def _bind_unhashed_operations(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT op_id,principal,job_id,kind,payload_sha256,result_json,revision,created_at "
            "FROM review_operations"
        ).fetchall()
        for row in rows:
            if row["result_json"] is None:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA", "legacy operation has no replay result"
                )
            result_sha256 = sha256_bytes(row["result_json"].encode("utf-8"))
            operation_sha256 = self._operation_sha256(
                op_id=row["op_id"],
                principal=row["principal"],
                job_id=row["job_id"],
                kind=row["kind"],
                payload_sha256=row["payload_sha256"],
                result_sha256=result_sha256,
                revision=row["revision"],
                created_at=row["created_at"],
            )
            conn.execute(
                "UPDATE review_operations SET result_sha256=?, operation_sha256=? "
                "WHERE op_id=?",
                (result_sha256, operation_sha256, row["op_id"]),
            )
            self._insert_audit(
                conn,
                event_id=self.new_event_id(),
                job_id=row["job_id"],
                kind=AUDIT_OPERATION_MIGRATED,
                payload={
                    "op_id": row["op_id"],
                    "operation_sha256": operation_sha256,
                },
                created_at=int(time.time() * 1000),
            )

    def _transform_prior_records(
        self, conn: sqlite3.Connection, *, from_schema: str = PRIOR_SCHEMA_VERSION
    ) -> None:
        for row in conn.execute("SELECT job_id, record_json FROM review_jobs").fetchall():
            try:
                record = json.loads(row["record_json"])
            except ValueError as exc:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior review job {row['job_id']} has an unparseable record",
                ) from exc
            if not isinstance(record, dict):
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior review job {row['job_id']} has a non-object record",
                )
            if record.get("schema_version") != from_schema:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior review job {row['job_id']} has schema_version "
                    f"{record.get('schema_version')!r}, not {from_schema!r}",
                )
            migrated = dict(record)
            migrated["schema_version"] = SCHEMA_VERSION
            try:
                canonical = ReviewJobRecord.model_validate(migrated).model_dump(mode="json")
            except ValidationError as exc:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior review job {row['job_id']} cannot be migrated "
                    "to the current model",
                ) from exc
            new_json = canonical_json_bytes(canonical).decode("utf-8")
            conn.execute(
                "UPDATE review_jobs SET record_json=?, record_sha256=? WHERE job_id=?",
                (new_json, sha256_bytes(new_json.encode("utf-8")), row["job_id"]),
            )
            self._insert_audit(
                conn,
                event_id=self.new_event_id(),
                job_id=row["job_id"],
                kind=AUDIT_JOB_MIGRATED,
                payload={
                    "from_schema": from_schema,
                    "to_schema": SCHEMA_VERSION,
                },
                created_at=int(time.time() * 1000),
            )

    def _migrate_prior_receipts(self, conn: sqlite3.Connection) -> None:
        for row in conn.execute(
            "SELECT receipt_id, receipt_json FROM review_validation_receipts "
            "WHERE challenge_id IS NULL"
        ).fetchall():
            try:
                receipt = json.loads(row["receipt_json"])
            except ValueError as exc:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior validation receipt {row['receipt_id']} is unparseable",
                ) from exc
            challenge_id = receipt.get("challenge_id") if isinstance(receipt, dict) else None
            if not isinstance(challenge_id, str) or not challenge_id:
                raise AdapterError(
                    "UNSUPPORTED_SCHEMA",
                    f"prior validation receipt {row['receipt_id']} cannot be bound "
                    "to a challenge and would be excluded from integrity verification",
                )
            conn.execute(
                "UPDATE review_validation_receipts SET challenge_id=? WHERE receipt_id=?",
                (challenge_id, row["receipt_id"]),
            )

    @staticmethod
    def new_event_id() -> str:
        return f"review_{secrets.token_hex(16)}"

    # -- audit journal --------------------------------------------------------
    def _insert_audit(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        job_id: str | None,
        kind: str,
        payload: dict,
        created_at: int,
    ) -> None:
        redacted = redact(payload)
        previous = conn.execute(
            "SELECT event_hash FROM review_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        material = json.dumps(
            {
                "event_id": event_id,
                "job_id": job_id,
                "kind": kind,
                "payload": redacted,
                "created_at": created_at,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        event_hash = hashlib.sha256(material).hexdigest()
        conn.execute(
            """
            INSERT INTO review_audit(
                event_id,job_id,kind,payload_json,created_at,
                previous_hash,event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                job_id,
                kind,
                json.dumps(redacted, sort_keys=True),
                created_at,
                previous_hash,
                event_hash,
            ),
        )

    def _verify_audit_chain_on(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT * FROM review_audit ORDER BY sequence"
        ).fetchall()
        previous = "0" * 64
        for index, row in enumerate(rows):
            if row["sequence"] != index + 1:
                raise AdapterError(
                    "AUDIT_INTEGRITY", "audit journal sequence is not contiguous"
                )
            payload = json.loads(row["payload_json"])
            material = json.dumps(
                {
                    "event_id": row["event_id"],
                    "job_id": row["job_id"],
                    "kind": row["kind"],
                    "payload": payload,
                    "created_at": row["created_at"],
                    "previous_hash": previous,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            if row["previous_hash"] != previous:
                raise AdapterError(
                    "AUDIT_INTEGRITY", "audit journal previous-hash linkage broken"
                )
            if row["event_hash"] != hashlib.sha256(material).hexdigest():
                raise AdapterError("AUDIT_INTEGRITY", "audit event hash mismatch")
            previous = row["event_hash"]

    def verify_audit_chain(self, job_id: str | None = None) -> list[dict]:
        with self._locked_connection() as conn:
            self._verify_audit_chain_on(conn)
            events = conn.execute(
                "SELECT * FROM review_audit ORDER BY sequence"
            ).fetchall()
        if job_id is not None:
            events = [dict(e) for e in events if e["job_id"] == job_id]
            with self._locked_connection() as conn:
                self._verify_challenges(conn, job_id)
                self._verify_receipts(conn, job_id)
                self._verify_terminal_consistency_on(conn, job_id, events)
        return events

    def _audit_references(
        self, conn: sqlite3.Connection, *, job_id: str, kind: str, field: str, value: str
    ) -> bool:
        rows = conn.execute(
            "SELECT payload_json FROM review_audit WHERE job_id=? AND kind=?",
            (job_id, kind),
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if payload.get(field) == value:
                return True
        return False

    def _verify_terminal_consistency_on(
        self, conn: sqlite3.Connection, job_id: str, events: list[dict]
    ) -> None:
        row = conn.execute(
            "SELECT phase FROM review_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None or row["phase"] not in TERMINAL_PHASES:
            return
        if not events:
            raise AdapterError("AUDIT_INTEGRITY", "terminal job has no audit events")
        terminal = [
            e
            for e in events
            if e["kind"] in _TERMINAL_EVENT_KINDS
            or (
                e["kind"] == AUDIT_PHASE_TRANSITION
                and json.loads(e["payload_json"]).get("to") in TERMINAL_PHASES
            )
        ]
        if not terminal or events[-1]["sequence"] != terminal[-1]["sequence"]:
            raise AdapterError(
                "AUDIT_INTEGRITY", "terminal job audit chain is inconsistent"
            )

    def _verify_challenges(self, conn: sqlite3.Connection, job_id: str) -> None:
        for row in conn.execute(
            "SELECT * FROM review_challenges WHERE job_id=?", (job_id,)
        ):
            if sha256_bytes(row["challenge_json"].encode("utf-8")) != row["challenge_sha256"]:
                raise AdapterError("CHALLENGE_INTEGRITY", "review challenge hash mismatch")
            if row["status"] not in CHALLENGE_STATUSES:
                raise AdapterError(
                    "CHALLENGE_INTEGRITY", "review challenge status is invalid"
                )
            if row["status"] == CHALLENGE_STATUS_CONSUMED and not self._audit_references(
                conn,
                job_id=job_id,
                kind=AUDIT_CHALLENGE_CONSUMED,
                field="challenge_id",
                value=row["challenge_id"],
            ):
                raise AdapterError(
                    "AUDIT_INTEGRITY", "consumed challenge has no audit event"
                )
            if row["status"] == CHALLENGE_STATUS_REVOKED and not self._audit_references(
                conn,
                job_id=job_id,
                kind=AUDIT_CHALLENGE_REVOKED,
                field="challenge_id",
                value=row["challenge_id"],
            ):
                raise AdapterError(
                    "AUDIT_INTEGRITY", "revoked challenge has no audit event"
                )

    def _verify_receipts(self, conn: sqlite3.Connection, job_id: str) -> None:
        # Every validation receipt is verified -- no legacy receipt may be
        # excluded from integrity verification.
        for row in conn.execute(
            "SELECT * FROM review_validation_receipts WHERE job_id=?",
            (job_id,),
        ):
            if sha256_bytes(row["receipt_json"].encode("utf-8")) != row["receipt_sha256"]:
                raise AdapterError("RECEIPT_INTEGRITY", "validation receipt hash mismatch")
            persisted = json.loads(row["receipt_json"])
            if (
                persisted.get("signing_key_id") != row["signing_key_id"]
                or persisted.get("signing_algorithm") != row["signing_algorithm"]
                or persisted.get("proof") != row["proof"]
            ):
                raise AdapterError(
                    "RECEIPT_INTEGRITY", "validation proof metadata mismatch"
                )
            if self.authority is not None:
                try:
                    self.authority.verify_validation(persisted)
                except (ValueError, ValidationError) as exc:
                    raise AdapterError(
                        "RECEIPT_AUTHENTICITY_FAILED",
                        "stored validation receipt is not authentic",
                    ) from exc
            if not self._audit_references(
                conn,
                job_id=job_id,
                kind=AUDIT_VALIDATION_RECEIPT_RECORDED,
                field="receipt_id",
                value=row["receipt_id"],
            ):
                raise AdapterError(
                    "AUDIT_INTEGRITY", "validation receipt has no audit event"
                )
        for row in conn.execute(
            "SELECT * FROM review_runner_receipts WHERE job_id=?", (job_id,)
        ):
            if sha256_bytes(row["receipt_json"].encode("utf-8")) != row["receipt_sha256"]:
                raise AdapterError("RECEIPT_INTEGRITY", "review runner receipt hash mismatch")
            persisted = json.loads(row["receipt_json"])
            if (
                persisted.get("signing_key_id") != row["signing_key_id"]
                or persisted.get("signing_algorithm") != row["signing_algorithm"]
                or persisted.get("proof") != row["proof"]
            ):
                raise AdapterError(
                    "RECEIPT_INTEGRITY", "review runner proof metadata mismatch"
                )
            if self.authority is not None:
                try:
                    self.authority.verify_review(persisted)
                except (ValueError, ValidationError) as exc:
                    raise AdapterError(
                        "RECEIPT_AUTHENTICITY_FAILED",
                        "stored review runner receipt is not authentic",
                    ) from exc
            if not self._audit_references(
                conn,
                job_id=job_id,
                kind=AUDIT_REVIEW_RECEIPT_RECORDED,
                field="receipt_id",
                value=row["receipt_id"],
            ):
                raise AdapterError(
                    "AUDIT_INTEGRITY", "review runner receipt has no audit event"
                )
        # Reverse: every receipt-recorded audit event must name an existing row
        # (detects a deleted receipt whose event survived).
        for kind, table in (
            (AUDIT_VALIDATION_RECEIPT_RECORDED, "review_validation_receipts"),
            (AUDIT_REVIEW_RECEIPT_RECORDED, "review_runner_receipts"),
        ):
            for row in conn.execute(
                "SELECT payload_json FROM review_audit WHERE job_id=? AND kind=?",
                (job_id, kind),
            ):
                payload = json.loads(row["payload_json"])
                receipt_id = payload.get("receipt_id")
                if not receipt_id:
                    continue
                match = conn.execute(
                    f"SELECT receipt_sha256 FROM {table} WHERE receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                if match is None:
                    raise AdapterError(
                        "AUDIT_INTEGRITY", "receipt audit event references a deleted receipt"
                    )
                if payload.get("receipt_sha256") != match["receipt_sha256"]:
                    raise AdapterError(
                        "AUDIT_INTEGRITY", "receipt audit event hash does not match the row"
                    )

    def evidence_material(self, job_id: str) -> dict:
        """Return verified receipt bodies and the global audit head for a capsule."""
        with self._locked_connection() as conn:
            self._verify_integrity(conn, job_id)
            audit_head = conn.execute(
                "SELECT sequence,event_hash FROM review_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()

            def receipts(table: str) -> list[dict]:
                rows = conn.execute(
                    f"SELECT receipt_id,receipt_json,receipt_sha256 FROM {table} "
                    "WHERE job_id=? ORDER BY created_at,receipt_id",
                    (job_id,),
                ).fetchall()
                return [
                    {
                        "receipt_id": row["receipt_id"],
                        "receipt_sha256": row["receipt_sha256"],
                        "body": json.loads(row["receipt_json"]),
                    }
                    for row in rows
                ]

            return {
                "review_receipts": receipts("review_runner_receipts"),
                "validation_receipts": receipts("review_validation_receipts"),
                "global_audit_head": (
                    {
                        "sequence": audit_head["sequence"],
                        "event_hash": audit_head["event_hash"],
                    }
                    if audit_head is not None
                    else None
                ),
            }

    def _verify_operations(self, conn: sqlite3.Connection, job_id: str) -> None:
        job = conn.execute(
            "SELECT revision, record_json FROM review_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if job is None:
            raise AdapterError("NOT_FOUND", "review job not found")
        for row in conn.execute(
            "SELECT * FROM review_operations WHERE job_id=?", (job_id,)
        ):
            result_json = row["result_json"]
            if (
                not isinstance(result_json, str)
                or sha256_bytes(result_json.encode("utf-8")) != row["result_sha256"]
                or self._operation_sha256(
                    op_id=row["op_id"],
                    principal=row["principal"],
                    job_id=row["job_id"],
                    kind=row["kind"],
                    payload_sha256=row["payload_sha256"],
                    result_sha256=row["result_sha256"],
                    revision=row["revision"],
                    created_at=row["created_at"],
                )
                != row["operation_sha256"]
            ):
                raise AdapterError("OPERATION_INTEGRITY", "review operation hash mismatch")
            try:
                result = json.loads(result_json)
            except ValueError as exc:
                raise AdapterError(
                    "OPERATION_INTEGRITY", "review operation result is invalid"
                ) from exc
            if (
                not isinstance(result, dict)
                or result.get("job_id") != job_id
                or not 0 < row["revision"] <= job["revision"]
            ):
                raise AdapterError(
                    "OPERATION_INTEGRITY", "review operation state binding is invalid"
                )
            if row["revision"] == job["revision"]:
                state = dict(result)
                state.pop("review_challenge", None)
                state.pop("verification_challenge", None)
                if canonical_json_bytes(state).decode("utf-8") != job["record_json"]:
                    raise AdapterError(
                        "OPERATION_INTEGRITY",
                        "review operation result does not match recorded job revision",
                    )
            if not self._audit_references(
                conn,
                job_id=job_id,
                kind=row["kind"],
                field="operation_sha256",
                value=row["operation_sha256"],
            ) and not self._audit_references(
                conn,
                job_id=job_id,
                kind=AUDIT_OPERATION_MIGRATED,
                field="operation_sha256",
                value=row["operation_sha256"],
            ):
                raise AdapterError(
                    "OPERATION_INTEGRITY", "review operation has no bound audit event"
                )
        for audit in conn.execute(
            "SELECT payload_json FROM review_audit WHERE job_id=?", (job_id,)
        ):
            payload = json.loads(audit["payload_json"])
            op_id = payload.get("op_id")
            operation_sha256 = payload.get("operation_sha256")
            if not op_id and not operation_sha256:
                continue
            operation = conn.execute(
                "SELECT operation_sha256 FROM review_operations WHERE op_id=?", (op_id,)
            ).fetchone()
            if operation is None or operation["operation_sha256"] != operation_sha256:
                raise AdapterError(
                    "OPERATION_INTEGRITY",
                    "review operation audit binding is missing or mismatched",
                )

    def _verify_gate_semantics(self, conn: sqlite3.Connection, job_id: str) -> None:
        row = conn.execute(
            "SELECT record_json FROM review_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None:
            raise AdapterError("NOT_FOUND", "review job not found")
        record = json.loads(row["record_json"])
        if record.get("phase") not in {PHASE_READY, PHASE_COMPLETE}:
            return
        if self.authority is None:
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED", "ready job requires receipt authority"
            )
        review_id = record.get("codex_audit", {}).get("receipt_id")
        validation_id = record.get("verification_evidence", {}).get("receipt_id")
        verified: dict[str, object] = {}
        for name, receipt_id, table, verifier, challenge_kind in (
            (
                "review",
                review_id,
                "review_runner_receipts",
                self.authority.verify_review,
                CHALLENGE_KIND_REVIEW,
            ),
            (
                "validation",
                validation_id,
                "review_validation_receipts",
                self.authority.verify_validation,
                CHALLENGE_KIND_VERIFICATION,
            ),
        ):
            receipt_row = conn.execute(
                f"SELECT receipt_json,challenge_id FROM {table} "
                "WHERE receipt_id=? AND job_id=?",
                (receipt_id, job_id),
            ).fetchone()
            if receipt_row is None:
                raise AdapterError("RECEIPT_INTEGRITY", "ready job receipt is missing")
            receipt = verifier(json.loads(receipt_row["receipt_json"]))
            challenge = conn.execute(
                "SELECT challenge_json,status FROM review_challenges "
                "WHERE challenge_id=? AND job_id=? AND kind=?",
                (receipt_row["challenge_id"], job_id, challenge_kind),
            ).fetchone()
            if challenge is None or challenge["status"] != CHALLENGE_STATUS_CONSUMED:
                raise AdapterError(
                    "CHALLENGE_INTEGRITY",
                    "ready job challenge is not authentic and consumed",
                )
            challenge_body = json.loads(challenge["challenge_json"])
            receipt_head = (
                receipt.after_head if name == "review" else receipt.current_head
            )
            receipt_diff = (
                receipt.after_diff_hash
                if name == "review"
                else receipt.current_diff_hash
            )
            if (
                receipt.challenge_id != challenge_body["challenge_id"]
                or receipt.challenge_nonce != challenge_body["nonce"]
                or receipt_head != challenge_body["current_head"]
                or receipt_diff != challenge_body["current_diff_hash"]
            ):
                raise AdapterError(
                    "RECEIPT_INTEGRITY", "ready job receipt/challenge binding mismatch"
                )
            verified[name] = receipt
        validation = verified["validation"]
        if validation.boundary_result != "PASSED" or validation.fail_count != 0:
            raise AdapterError(
                "RECEIPT_INTEGRITY", "ready job validation receipt is not passing"
            )

    def _verify_job_integrity_on(
        self, conn: sqlite3.Connection, job_id: str, *, verify_operations: bool = True
    ) -> None:
        """Verify one job's record/challenge/receipt/terminal consistency inside
        the current transaction, without re-walking the global audit chain."""
        row = conn.execute(
            "SELECT record_json, record_sha256 FROM review_jobs WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise AdapterError("NOT_FOUND", "review job not found")
        if sha256_bytes(row["record_json"].encode("utf-8")) != row["record_sha256"]:
            raise AdapterError("RECORD_INTEGRITY", "review job record hash mismatch")
        self._verify_challenges(conn, job_id)
        self._verify_receipts(conn, job_id)
        self._verify_gate_semantics(conn, job_id)
        if verify_operations:
            self._verify_operations(conn, job_id)
        events = [
            dict(e)
            for e in conn.execute(
                "SELECT * FROM review_audit WHERE job_id=? ORDER BY sequence",
                (job_id,),
            ).fetchall()
        ]
        self._verify_terminal_consistency_on(conn, job_id, events)

    def _verify_integrity(
        self, conn: sqlite3.Connection, job_id: str, *, include_anchor: bool = True
    ) -> None:
        """Verify record/audit/challenge/receipt consistency inside the current
        transaction. Called on every mutation immediately before commit."""
        self._verify_job_integrity_on(conn, job_id)
        self._verify_audit_chain_on(conn)
        if include_anchor:
            self._verify_anchor(conn)

    # -- create ---------------------------------------------------------------
    def replay_create(self, job_id: str, request_sha256: str) -> dict | None:
        with self._locked_connection() as conn:
            row = conn.execute(
                "SELECT request_sha256,record_json FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if row is None:
                return None
            self._verify_integrity(conn, job_id)
            if row["request_sha256"] != request_sha256:
                raise AdapterError(
                    "IDEMPOTENCY_CONFLICT",
                    "job_id is bound to a different create payload",
                )
            return json.loads(row["record_json"])

    def create(
        self,
        job_id: str,
        owner_principal: str,
        request_sha256: str,
        record: dict,
    ) -> tuple[dict, bool]:
        record_bytes = canonical_json_bytes(record)
        record_sha256 = sha256_bytes(record_bytes)
        now = int(time.time() * 1000)
        with self._locked_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT record_json, record_sha256, request_sha256 "
                "FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if existing:
                self._verify_hash(existing["record_json"], existing["record_sha256"])
                if existing["request_sha256"] != request_sha256:
                    conn.rollback()
                    raise AdapterError(
                        "IDEMPOTENCY_CONFLICT",
                        "job_id is bound to a different create payload",
                    )
                conn.commit()
                return json.loads(existing["record_json"]), False
            conn.execute(
                """
                INSERT INTO review_jobs(
                    job_id,request_sha256,owner_principal,phase,status,
                    revision,created_at,updated_at,record_json,record_sha256
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    request_sha256,
                    owner_principal,
                    record["phase"],
                    record["status"],
                    now,
                    now,
                    record_bytes.decode("utf-8"),
                    record_sha256,
                ),
            )
            self._insert_audit(
                conn,
                event_id=self.new_event_id(),
                job_id=job_id,
                kind=AUDIT_JOB_CREATED,
                payload={
                    "phase": record["phase"],
                    "request_sha256": request_sha256,
                    "repository_id": record["repository_id"],
                    "starting_sha": record["starting_sha"],
                },
                created_at=now,
            )
            self._verify_integrity(conn, job_id, include_anchor=False)
            self._commit_with_anchor(conn)
            return dict(record), True

    @staticmethod
    def _verify_hash(record_json: str, record_sha256: str) -> None:
        if sha256_bytes(record_json.encode("utf-8")) != record_sha256:
            raise AdapterError(
                "RECORD_INTEGRITY", "review job record hash mismatch"
            )

    # -- reads ----------------------------------------------------------------
    def get(self, job_id: str) -> dict | None:
        with self._locked_connection() as conn:
            conn.execute("BEGIN")
            row = conn.execute(
                "SELECT record_json, record_sha256 FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            self._verify_integrity(conn, job_id)
            row = conn.execute(
                "SELECT record_json, record_sha256 FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            record = json.loads(row["record_json"])
            conn.commit()
            return record

    def get_owner(self, job_id: str) -> str | None:
        with self._locked_connection() as conn:
            row = conn.execute(
                "SELECT owner_principal FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
        return row["owner_principal"] if row else None

    def get_revision(self, job_id: str) -> int | None:
        with self._locked_connection() as conn:
            row = conn.execute(
                "SELECT revision FROM review_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        return int(row["revision"]) if row else None

    def list(
        self,
        *,
        phase: str | None = None,
        status: str | None = None,
        owner: str | None = None,
    ) -> list[dict]:
        query = "SELECT record_json, record_sha256, job_id FROM review_jobs"
        clauses: list[str] = []
        values: list[object] = []
        if phase is not None:
            clauses.append("phase=?")
            values.append(phase)
        if status is not None:
            clauses.append("status=?")
            values.append(status)
        if owner is not None:
            clauses.append("owner_principal=?")
            values.append(owner)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._locked_connection() as conn:
            conn.execute("BEGIN")
            self._verify_audit_chain_on(conn)
            rows = conn.execute(query, values).fetchall()
            records = []
            for row in rows:
                self._verify_job_integrity_on(conn, row["job_id"])
                records.append(json.loads(row["record_json"]))
            conn.commit()
            return records

    # -- challenges -----------------------------------------------------------
    def issue_challenge(self, challenge: dict) -> dict:
        with self._locked_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._verify_integrity(conn, challenge["job_id"])
                self._revoke_active_challenges(
                    conn,
                    challenge["job_id"],
                    challenge["kind"],
                    superseded_by=challenge["challenge_id"],
                    now_iso=_utc_now(),
                )
                self._insert_challenge(conn, challenge)
                self._verify_integrity(
                    conn, challenge["job_id"], include_anchor=False
                )
                self._commit_with_anchor(conn)
            except Exception:
                conn.rollback()
                raise
        return dict(challenge)

    def get_active_challenge(self, job_id: str, kind: str) -> dict | None:
        with self._locked_connection() as conn:
            row = conn.execute(
                "SELECT challenge_json, challenge_sha256 FROM review_challenges "
                "WHERE job_id=? AND kind=? AND status=? ORDER BY issued_at DESC LIMIT 1",
                (job_id, kind, CHALLENGE_STATUS_ACTIVE),
            ).fetchone()
        if not row:
            return None
        if sha256_bytes(row["challenge_json"].encode("utf-8")) != row["challenge_sha256"]:
            raise AdapterError("CHALLENGE_INTEGRITY", "review challenge hash mismatch")
        return json.loads(row["challenge_json"])

    # -- idempotency replay (public, read-only) -------------------------------
    def replay(
        self,
        op_id: str,
        *,
        principal: str,
        job_id: str,
        kind: str,
        payload_sha256: str,
    ) -> dict | None:
        if not op_id:
            return None
        with self._locked_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT principal, job_id, kind, payload_sha256, result_json "
                    "FROM review_operations WHERE op_id=?",
                    (op_id,),
                ).fetchone()
                if row is None:
                    conn.commit()
                    return None
                if (
                    row["principal"],
                    row["job_id"],
                    row["kind"],
                    row["payload_sha256"],
                ) != (principal, job_id, kind, payload_sha256):
                    conn.rollback()
                    raise AdapterError(
                        "IDEMPOTENCY_CONFLICT",
                        "operation id is bound to a different principal/job/kind/payload",
                    )
                result = json.loads(row["result_json"])
                # Verify the target job's full record/audit/challenge/receipt
                # integrity in the same transaction before returning the saved
                # result, so a tampered store can never replay a stale success.
                self._verify_integrity(conn, job_id)
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    # -- challenge helpers (within an open transaction) -----------------------
    def _revoke_active_challenges(
        self,
        conn: sqlite3.Connection,
        job_id: str,
        kind: str,
        *,
        superseded_by: str,
        now_iso: str,
    ) -> None:
        rows = conn.execute(
            "SELECT challenge_id FROM review_challenges "
            "WHERE job_id=? AND kind=? AND status=?",
            (job_id, kind, CHALLENGE_STATUS_ACTIVE),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE review_challenges SET status=?, revoked_at=?, superseded_by=? "
                "WHERE challenge_id=? AND status=?",
                (
                    CHALLENGE_STATUS_REVOKED,
                    now_iso,
                    superseded_by,
                    row["challenge_id"],
                    CHALLENGE_STATUS_ACTIVE,
                ),
            )
            self._insert_audit(
                conn,
                event_id=self.new_event_id(),
                job_id=job_id,
                kind=AUDIT_CHALLENGE_REVOKED,
                payload={
                    "challenge_id": row["challenge_id"],
                    "superseded_by": superseded_by,
                },
                created_at=int(time.time() * 1000),
            )

    def _insert_challenge(self, conn: sqlite3.Connection, challenge: dict) -> None:
        challenge_bytes = canonical_json_bytes(challenge)
        challenge_sha256 = sha256_bytes(challenge_bytes)
        conn.execute(
            """
            INSERT INTO review_challenges(
                challenge_id,job_id,kind,principal,round,nonce,prompt_sha256,
                issued_at,expires_at,status,challenge_json,challenge_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge["challenge_id"],
                challenge["job_id"],
                challenge["kind"],
                challenge["principal"],
                challenge["review_round"],
                challenge["nonce"],
                challenge.get("prompt_sha256"),
                challenge["issued_at"],
                challenge["expires_at"],
                challenge["status"],
                challenge_bytes.decode("utf-8"),
                challenge_sha256,
            ),
        )
        self._insert_audit(
            conn,
            event_id=self.new_event_id(),
            job_id=challenge["job_id"],
            kind=AUDIT_CHALLENGE_ISSUED,
            payload={
                "challenge_id": challenge["challenge_id"],
                "kind": challenge["kind"],
                "round": challenge["review_round"],
            },
            created_at=int(time.time() * 1000),
        )

    def _consume_challenge(
        self,
        conn: sqlite3.Connection,
        expected: dict,
        *,
        op_id: str | None,
        now_iso: str,
    ) -> None:
        """Load the submitted challenge by its id and require exact equality
        with the server-issued active challenge, then consume it once."""
        challenge_id = expected["challenge_id"]
        row = conn.execute(
            "SELECT * FROM review_challenges WHERE challenge_id=?", (challenge_id,)
        ).fetchone()
        if not row:
            raise AdapterError(
                "CHALLENGE_UNAVAILABLE", "review challenge is not found"
            )
        if sha256_bytes(row["challenge_json"].encode("utf-8")) != row["challenge_sha256"]:
            raise AdapterError("CHALLENGE_INTEGRITY", "review challenge hash mismatch")
        if row["status"] != CHALLENGE_STATUS_ACTIVE:
            raise AdapterError("CHALLENGE_REPLAY", "review challenge was already used")
        # Exact equality against the server-issued challenge just validated.
        stored = json.loads(row["challenge_json"])
        if stored != expected:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "review challenge does not match the active challenge"
            )
        if row["job_id"] != expected["job_id"]:
            raise AdapterError("CHALLENGE_MISMATCH", "review challenge is bound to another job")
        if row["kind"] != expected["kind"]:
            raise AdapterError("CHALLENGE_MISMATCH", "review challenge kind mismatch")
        if row["principal"] != expected["principal"]:
            raise AdapterError(
                "ROLE_VIOLATION", "review challenge is bound to another principal"
            )
        if _parse_ts(now_iso) > _parse_ts(row["expires_at"]):
            raise AdapterError("CHALLENGE_EXPIRED", "review challenge has expired")
        # At most one consumable active challenge: a second ACTIVE row for the
        # same job/kind means this id was concurrently superseded.
        others = conn.execute(
            "SELECT COUNT(*) FROM review_challenges WHERE job_id=? AND kind=? "
            "AND status=? AND challenge_id != ?",
            (
                expected["job_id"],
                expected["kind"],
                CHALLENGE_STATUS_ACTIVE,
                challenge_id,
            ),
        ).fetchone()
        if others[0] != 0:
            raise AdapterError(
                "CHALLENGE_SUPERSEDED", "review challenge was concurrently superseded"
            )
        changed = conn.execute(
            "UPDATE review_challenges SET status=?, consumed_at=?, consumed_op_id=? "
            "WHERE challenge_id=? AND status=?",
            (
                CHALLENGE_STATUS_CONSUMED,
                now_iso,
                op_id,
                challenge_id,
                CHALLENGE_STATUS_ACTIVE,
            ),
        )
        if changed.rowcount != 1:
            raise AdapterError("CHALLENGE_REPLAY", "review challenge was already used")
        self._insert_audit(
            conn,
            event_id=self.new_event_id(),
            job_id=expected["job_id"],
            kind=AUDIT_CHALLENGE_CONSUMED,
            payload={
                "challenge_id": challenge_id,
                "kind": expected["kind"],
                "consumed_op_id": op_id,
            },
            created_at=int(time.time() * 1000),
        )

    # -- receipt persistence (within an open transaction) ---------------------
    def _insert_review_receipt(
        self, conn: sqlite3.Connection, receipt: dict, *, created_at: int
    ) -> None:
        receipt_bytes = canonical_json_bytes(receipt)
        receipt_sha256 = sha256_bytes(receipt_bytes)
        try:
            conn.execute(
                """
                INSERT INTO review_runner_receipts(
                    receipt_id,job_id,challenge_id,receipt_json,receipt_sha256,
                    signing_key_id,signing_algorithm,proof,created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt["receipt_id"],
                    receipt["job_id"],
                    receipt["challenge_id"],
                    receipt_bytes.decode("utf-8"),
                    receipt_sha256,
                    receipt["signing_key_id"],
                    receipt["signing_algorithm"],
                    receipt["proof"],
                    created_at,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AdapterError(
                "RECEIPT_REPLAY", "review runner receipt was already recorded"
            ) from exc
        self._insert_audit(
            conn,
            event_id=self.new_event_id(),
            job_id=receipt["job_id"],
            kind=AUDIT_REVIEW_RECEIPT_RECORDED,
            payload={
                "receipt_id": receipt["receipt_id"],
                "challenge_id": receipt["challenge_id"],
                "receipt_sha256": receipt_sha256,
            },
            created_at=created_at,
        )

    def _insert_validation_receipt(
        self, conn: sqlite3.Connection, receipt: dict, *, created_at: int
    ) -> None:
        receipt_bytes = canonical_json_bytes(receipt)
        receipt_sha256 = sha256_bytes(receipt_bytes)
        try:
            conn.execute(
                """
                INSERT INTO review_validation_receipts(
                    receipt_id,job_id,challenge_id,snapshot_sha,
                    receipt_json,receipt_sha256,signing_key_id,signing_algorithm,proof,created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt["receipt_id"],
                    receipt["job_id"],
                    receipt["challenge_id"],
                    receipt["snapshot_sha"],
                    receipt_bytes.decode("utf-8"),
                    receipt_sha256,
                    receipt["signing_key_id"],
                    receipt["signing_algorithm"],
                    receipt["proof"],
                    created_at,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AdapterError(
                "RECEIPT_REPLAY", "validation receipt was already recorded"
            ) from exc
        self._insert_audit(
            conn,
            event_id=self.new_event_id(),
            job_id=receipt["job_id"],
            kind=AUDIT_VALIDATION_RECEIPT_RECORDED,
            payload={
                "receipt_id": receipt["receipt_id"],
                "challenge_id": receipt["challenge_id"],
                "snapshot_sha": receipt["snapshot_sha"],
                "receipt_sha256": receipt_sha256,
            },
            created_at=created_at,
        )

    # -- transition (single atomic mutation) ----------------------------------
    def transition(
        self,
        job_id: str,
        *,
        expected_phase: str,
        expected_revision: int | None,
        record: dict,
        event_kind: str,
        event_payload: dict,
        op_id: str | None = None,
        payload_sha256: str | None = None,
        op_principal: str | None = None,
        challenge_consume: dict | None = None,
        challenge_issue: dict | None = None,
        review_receipt: dict | None = None,
        validation_receipt: dict | None = None,
        operation_result: dict | None = None,
    ) -> dict:
        """Compare-and-swap the job's phase/revision and write the new record,
        consume/issue challenges, persist receipts, and record an op-id, all in
        one transaction. Replay lookup happens before any mutable-state check.
        """
        record_bytes = canonical_json_bytes(record)
        record_sha256 = sha256_bytes(record_bytes)
        now = int(time.time() * 1000)
        now_iso = _utc_now()
        with self._locked_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")

            # Idempotent replay BEFORE phase/challenge/receipt checks.
            if op_id:
                existing = conn.execute(
                    "SELECT principal, job_id, kind, payload_sha256, result_json "
                    "FROM review_operations WHERE op_id=?",
                    (op_id,),
                ).fetchone()
                if existing:
                    if (
                        existing["principal"],
                        existing["job_id"],
                        existing["kind"],
                        existing["payload_sha256"],
                    ) != (op_principal, job_id, event_kind, payload_sha256):
                        conn.rollback()
                        raise AdapterError(
                            "IDEMPOTENCY_CONFLICT",
                            "operation id is bound to a different principal/job/kind/payload",
                        )
                    result = json.loads(existing["result_json"])
                    # Verify the target job/audit/challenge/receipt integrity in
                    # the same transaction before returning the replay, so a
                    # tampered store can never replay a stale success.
                    self._verify_integrity(conn, job_id)
                    conn.commit()
                    return result

            if challenge_consume is not None:
                self._consume_challenge(
                    conn, challenge_consume, op_id=op_id, now_iso=now_iso
                )

            row = conn.execute(
                "SELECT phase, revision, record_json, record_sha256 "
                "FROM review_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if not row:
                conn.rollback()
                raise AdapterError("NOT_FOUND", "review job not found")
            if row["phase"] != expected_phase:
                conn.rollback()
                raise AdapterError(
                    "STALE_TRANSITION",
                    f"review job phase moved (expected {expected_phase}, "
                    f"found {row['phase']})",
                )
            if expected_revision is not None and row["revision"] != expected_revision:
                conn.rollback()
                raise AdapterError(
                    "STALE_TRANSITION", "review job was updated concurrently"
                )
            self._verify_hash(row["record_json"], row["record_sha256"])

            changed = conn.execute(
                """
                UPDATE review_jobs
                SET phase=?, status=?, revision=revision+1, updated_at=?,
                    record_json=?, record_sha256=?
                WHERE job_id=? AND revision=?
                """,
                (
                    record["phase"],
                    record["status"],
                    now,
                    record_bytes.decode("utf-8"),
                    record_sha256,
                    job_id,
                    row["revision"],
                ),
            )
            if changed.rowcount != 1:
                conn.rollback()
                raise AdapterError(
                    "STALE_TRANSITION", "review job was updated concurrently"
                )

            if review_receipt is not None:
                self._insert_review_receipt(conn, review_receipt, created_at=now)
            if validation_receipt is not None:
                self._insert_validation_receipt(conn, validation_receipt, created_at=now)
            if challenge_issue is not None:
                self._revoke_active_challenges(
                    conn,
                    challenge_issue["job_id"],
                    challenge_issue["kind"],
                    superseded_by=challenge_issue["challenge_id"],
                    now_iso=now_iso,
                )
                self._insert_challenge(conn, challenge_issue)

            audit_payload = dict(event_payload)
            result_bytes = None
            result_sha256 = None
            operation_sha256 = None
            if op_id:
                result_bytes = canonical_json_bytes(operation_result or record)
                result_sha256 = sha256_bytes(result_bytes)
                operation_sha256 = self._operation_sha256(
                    op_id=op_id,
                    principal=op_principal,
                    job_id=job_id,
                    kind=event_kind,
                    payload_sha256=payload_sha256,
                    result_sha256=result_sha256,
                    revision=row["revision"] + 1,
                    created_at=now,
                )
                audit_payload.update(
                    {"op_id": op_id, "operation_sha256": operation_sha256}
                )
            self._insert_audit(
                conn,
                event_id=self.new_event_id(),
                job_id=job_id,
                kind=event_kind,
                payload=audit_payload,
                created_at=now,
            )

            if op_id:
                conn.execute(
                    """
                    INSERT INTO review_operations(
                        op_id,principal,job_id,kind,payload_sha256,
                        result_json,result_sha256,revision,created_at,operation_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        op_id,
                        op_principal,
                        job_id,
                        event_kind,
                        payload_sha256,
                        result_bytes.decode("utf-8"),
                        result_sha256,
                        row["revision"] + 1,
                        now,
                        operation_sha256,
                    ),
                )

            self._verify_integrity(conn, job_id, include_anchor=False)
            self._commit_with_anchor(conn)
            return dict(record)


# ── Orchestrator ─────────────────────────────────────────────────────────────
class ReviewOrchestrator:
    """Bounded review-orchestration operations over a ``ReviewStore``.

    ``git`` (the server-observed snapshot boundary), ``authority`` (the
    runner/validator receipt verifier), and ``repository_roots`` (trusted
    worktree roots) are required for any gate-crossing operation; without them
    the gate fails closed.
    """

    def __init__(
        self,
        store: ReviewStore,
        *,
        git: GitVerifier | None = None,
        authority: ReceiptAuthority | None = None,
        repository_roots=(),
    ):
        self.store = store
        self.git = git
        self.authority = authority
        self.store.attach_authority(authority)
        self._repository_roots = frozenset(Path(root) for root in repository_roots)

    # -- load / fail closed ---------------------------------------------------
    def _load(self, job_id: str) -> dict:
        record = self.store.get(job_id)
        if record is None:
            raise AdapterError("NOT_FOUND", "review job not found")
        return self._validate_record(record)

    @staticmethod
    def _validate_record(record: dict) -> dict:
        try:
            model = ReviewJobRecord.model_validate(record)
        except ValidationError as exc:
            raise AdapterError(
                "INVALID_STATE", "persisted review job is invalid or unsupported"
            ) from exc
        if model.schema_version != SCHEMA_VERSION:
            raise AdapterError(
                "INVALID_STATE",
                f"unsupported review job schema_version {model.schema_version}",
            )
        return model.model_dump(mode="json")

    @staticmethod
    def _require_owner(actor: str, record: dict) -> None:
        if actor != record.get("owner_principal"):
            raise AdapterError(
                "AUTHORIZATION_FAILED",
                "principal does not own this review job",
            )

    def _require_owner_by_id(self, actor: str, job_id: str) -> None:
        owner = self.store.get_owner(job_id)
        if owner is None:
            raise AdapterError("NOT_FOUND", "review job not found")
        if actor != owner:
            raise AdapterError(
                "AUTHORIZATION_FAILED", "principal does not own this review job"
            )

    def _require_authority(self) -> ReceiptAuthority:
        if self.authority is None:
            raise AdapterError(
                "CAPABILITY_UNAVAILABLE",
                "trusted receipt authority is not configured",
            )
        return self.authority

    def _observe(self, record: dict) -> dict:
        if self.git is None:
            raise AdapterError(
                "CAPABILITY_UNAVAILABLE", "trusted snapshot observer is not configured"
            )
        return self.git.observe_review_snapshot(
            record["worktree_path"],
            repository_id=record["repository_id"],
            branch=record["branch"],
            starting_sha=record["starting_sha"],
            allowed_paths=record["allowed_paths"],
            allowed_roots=self._repository_roots,
        )

    def _canonical_worktree(self, worktree_path: str) -> str:
        return str(
            GitVerifier.canonical_worktree_root(worktree_path, self._repository_roots)
        )

    # -- challenge builders ---------------------------------------------------
    def _build_challenge(
        self,
        record: dict,
        kind: str,
        *,
        principal: str,
        review_round: int,
        prompt_sha256: str | None = None,
    ) -> dict:
        challenge_id = secrets.token_hex(32)
        challenge = {
            "challenge_id": challenge_id,
            "kind": kind,
            "job_id": record["job_id"],
            "principal": principal,
            "nonce": secrets.token_hex(16),
            "issued_at": _utc_now(),
            "expires_at": _now_plus(self.store.challenge_ttl_seconds),
            "repository_id": record["repository_id"],
            "worktree_path": record["worktree_path"],
            "branch": record["branch"],
            "starting_sha": record["starting_sha"],
            "current_head": record["current_head"],
            "current_diff_hash": record["current_diff_hash"],
            "allowed_paths": list(record["allowed_paths"]),
            "review_round": review_round,
            "status": CHALLENGE_STATUS_ACTIVE,
        }
        if kind == CHALLENGE_KIND_REVIEW:
            challenge["prompt_sha256"] = prompt_sha256
        return challenge

    def _issue_review_challenge(self, record: dict, prompt_sha256: str) -> dict:
        return self._build_challenge(
            record,
            CHALLENGE_KIND_REVIEW,
            principal=ACTOR_CODEX,
            review_round=record["review_round"] + 1,
            prompt_sha256=prompt_sha256,
        )

    def _issue_verification_challenge(self, record: dict) -> dict:
        return self._build_challenge(
            record,
            CHALLENGE_KIND_VERIFICATION,
            principal=ACTOR_HERMES,
            review_round=record["review_round"],
        )

    def _active_challenge(self, job_id: str, kind: str) -> dict:
        challenge = self.store.get_active_challenge(job_id, kind)
        if challenge is None:
            raise AdapterError(
                "CHALLENGE_UNAVAILABLE", f"no active {kind} challenge is issued"
            )
        return challenge

    def active_challenge(self, job_id: str, kind: str) -> dict:
        """Public accessor for the trusted runtime's internal dispatch."""
        challenge = self._active_challenge(job_id, kind)
        self._assert_challenge_snapshot(challenge, self._load(job_id))
        return challenge

    def _assert_challenge_snapshot(self, challenge: dict, record: dict) -> None:
        if (
            challenge["job_id"] != record["job_id"]
            or challenge["current_head"] != record["current_head"]
            or challenge["current_diff_hash"] != record["current_diff_hash"]
            or list(challenge["allowed_paths"]) != list(record["allowed_paths"])
        ):
            raise AdapterError(
                "CHALLENGE_MISMATCH",
                "challenge is not bound to the current job snapshot",
            )
        observed = self._observe(record)
        if (
            observed["head"] != challenge["current_head"]
            or observed["diff_hash"] != challenge["current_diff_hash"]
        ):
            raise AdapterError(
                "SNAPSHOT_STALE",
                "worktree baseline or snapshot changed after challenge issuance",
            )

    # -- create ---------------------------------------------------------------
    def create(self, actor: str, payload: dict) -> dict:
        if actor != ACTOR_HERMES:
            raise AdapterError(
                "ROLE_VIOLATION", "only Hermes may create review-orchestration jobs"
            )
        try:
            intent = ReviewJobCreate.model_validate(payload)
        except ValidationError as exc:
            raise AdapterError("INVALID_REQUEST", "create request is invalid") from exc
        request_sha256 = canonical_sha256(payload)
        replay = self.store.replay_create(intent.job_id, request_sha256)
        if replay is not None:
            self._require_owner(actor, replay)
            return replay
        worktree_path = self._canonical_worktree(intent.worktree_path)
        observer = self.git or GitVerifier({})
        baseline = observer.observe_review_baseline(
            worktree_path,
            repository_id=intent.repository_id,
            branch=intent.branch,
            starting_sha=intent.starting_sha,
            allowed_roots=self._repository_roots,
            require_allowlisted_remote=self.git is not None,
        )
        if (
            intent.current_head is not None
            and intent.current_head != baseline["current_head"]
        ):
            raise AdapterError(
                "HEAD_MISMATCH",
                "caller current_head does not match server-observed HEAD",
            )
        record = {
            "job_id": intent.job_id,
            "schema_version": SCHEMA_VERSION,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "repository_id": intent.repository_id,
            "worktree_path": worktree_path,
            "branch": intent.branch,
            "starting_sha": baseline["starting_sha"],
            "baseline_evidence": baseline,
            "current_head": baseline["current_head"],
            "current_diff_hash": "",
            "phase": PHASE_QUEUED,
            "status": STATUS_ACTIVE,
            "active_worker": None,
            "delegation_id": intent.delegation_id,
            "review_round": 0,
            "codex_thread_id": None,
            "codex_cli_version": None,
            "codex_audit": {},
            "blocker_count": 0,
            "major_count": 0,
            "minor_count": 0,
            "findings": [],
            "last_focused_test": None,
            "last_full_test": None,
            "verification_evidence": {},
            "block_reason": "",
            "next_action": "begin implementation",
            "merge_ready": False,
            "allowed_paths": list(intent.allowed_paths),
            "architecture_anchors": list(intent.architecture_anchors),
            "acceptance_anchors": list(intent.acceptance_anchors),
            "blocking_phase": None,
            "resume_target": None,
            "owner_principal": actor,
        }
        validated = self._validate_record(record)
        stored, _created = self.store.create(
            intent.job_id, actor, request_sha256, validated
        )
        return stored

    # -- read -----------------------------------------------------------------
    def get(self, actor: str, job_id: str) -> dict:
        record = self._load(job_id)
        self._require_owner(actor, record)
        return record

    def list(
        self,
        actor: str,
        *,
        phase: str | None = None,
        status: str | None = None,
    ) -> dict:
        if phase is not None and phase not in PHASES:
            raise AdapterError("INVALID_REQUEST", f"unsupported phase filter: {phase}")
        if status is not None and status not in STATUSES:
            raise AdapterError("INVALID_REQUEST", f"unsupported status filter: {status}")
        records = [
            self._validate_record(r)
            for r in self.store.list(phase=phase, status=status, owner=actor)
        ]
        return {"jobs": records}

    def review_challenge(self, actor: str, job_id: str) -> dict:
        record = self._load(job_id)
        self._require_owner(actor, record)
        challenge = self._active_challenge(job_id, CHALLENGE_KIND_REVIEW)
        self._assert_challenge_snapshot(challenge, record)
        return challenge

    def verification_challenge(self, actor: str, job_id: str) -> dict:
        record = self._load(job_id)
        self._require_owner(actor, record)
        challenge = self._active_challenge(job_id, CHALLENGE_KIND_VERIFICATION)
        self._assert_challenge_snapshot(challenge, record)
        return challenge

    # -- transition -----------------------------------------------------------
    def transition(self, actor: str, job_id: str, payload: dict) -> dict:
        if actor != ACTOR_HERMES:
            raise AdapterError(
                "ROLE_VIOLATION", "only Hermes may drive orchestration transitions"
            )
        try:
            request = TransitionRequest.model_validate(payload)
        except ValidationError as exc:
            raise AdapterError("INVALID_REQUEST", "transition request is invalid") from exc
        target = request.target_phase
        if target not in PHASES:
            raise AdapterError("INVALID_REQUEST", f"unsupported phase: {target}")
        payload_sha256 = canonical_sha256(payload)
        replayed = self.store.replay(
            request.op_id,
            principal=actor,
            job_id=job_id,
            kind=AUDIT_PHASE_TRANSITION,
            payload_sha256=payload_sha256,
        )
        if replayed is not None:
            return replayed
        record = self._load(job_id)
        self._require_owner(actor, record)
        revision = self.store.get_revision(job_id)
        current = record["phase"]
        if request.expected_phase is not None and request.expected_phase != current:
            raise AdapterError(
                "STALE_TRANSITION",
                f"expected phase {request.expected_phase} but job is {current}",
            )
        if current in TERMINAL_PHASES:
            raise AdapterError(
                "TERMINAL_STATE_CONFLICT", f"terminal phase {current} cannot transition"
            )
        if target not in ORCHESTRATOR_TRANSITIONS.get(current, frozenset()):
            raise AdapterError(
                "INVALID_TRANSITION", f"illegal transition {current} -> {target}"
            )

        if current == PHASE_BLOCKED:
            resume_target = record.get("resume_target")
            if target == PHASE_FAILED:
                pass
            elif resume_target is None:
                raise AdapterError(
                    "INVALID_TRANSITION", "blocked job has no recorded resume target"
                )
            elif target != resume_target:
                raise AdapterError(
                    "INVALID_TRANSITION",
                    f"blocked job may only resume into {resume_target}, not {target}",
                )

        # Server-observed snapshot is required to enter a gate and to complete.
        snapshot = None
        if target in {PHASE_REVIEWING, PHASE_VERIFYING, PHASE_COMPLETE}:
            snapshot = self._observe(record)

        if target == PHASE_REVIEWING:
            if not request.prompt_sha256:
                raise AdapterError(
                    "INVALID_REQUEST", "prompt_sha256 is required to enter REVIEWING"
                )
            record["current_head"] = snapshot["head"]
            record["current_diff_hash"] = snapshot["diff_hash"]
        elif target == PHASE_VERIFYING:
            record["current_head"] = snapshot["head"]
            record["current_diff_hash"] = snapshot["diff_hash"]
        elif target == PHASE_COMPLETE:
            # COMPLETE requires the worktree still to be exactly the snapshot
            # that was clean-reviewed and validated. Any drift invalidates
            # readiness and blocks completion.
            if (
                snapshot["head"] != record["current_head"]
                or snapshot["diff_hash"] != record["current_diff_hash"]
            ):
                raise AdapterError(
                    "SNAPSHOT_STALE",
                    "worktree drifted after verification; a fresh review and "
                    "verification round is required",
                )

        challenge_issue = None
        self._apply_phase(
            record,
            target,
            delegation_id=request.delegation_id,
            next_action=request.next_action,
            block_reason=request.block_reason,
            blocking_phase=current if target == PHASE_BLOCKED else None,
        )
        if current == PHASE_BLOCKED and target != PHASE_BLOCKED:
            record["blocking_phase"] = None
            record["resume_target"] = None

        if target == PHASE_REVIEWING:
            challenge_issue = self._issue_review_challenge(
                record, request.prompt_sha256
            )
        elif target == PHASE_VERIFYING:
            challenge_issue = self._issue_verification_challenge(record)

        operation_result = dict(record)
        if challenge_issue is not None:
            if target == PHASE_REVIEWING:
                operation_result["review_challenge"] = challenge_issue
            elif target == PHASE_VERIFYING:
                operation_result["verification_challenge"] = challenge_issue
        self.store.transition(
            job_id,
            expected_phase=current,
            expected_revision=revision,
            record=record,
            event_kind=AUDIT_PHASE_TRANSITION,
            event_payload={"from": current, "to": target, "actor": actor},
            op_id=request.op_id,
            payload_sha256=payload_sha256,
            op_principal=actor,
            challenge_issue=challenge_issue,
            operation_result=operation_result,
        )
        return operation_result

    def _apply_phase(
        self,
        record: dict,
        target: str,
        *,
        delegation_id: str | None = None,
        next_action: str | None = None,
        block_reason: str | None = None,
        blocking_phase: str | None = None,
    ) -> None:
        record["phase"] = target
        record["active_worker"] = PHASE_OWNER.get(target)
        record["status"] = self._status_for_phase(target)
        if delegation_id is not None:
            record["delegation_id"] = delegation_id
        if next_action is not None:
            record["next_action"] = next_action
        if target == PHASE_BLOCKED:
            record["block_reason"] = block_reason or record["block_reason"] or "blocked"
            record["blocking_phase"] = blocking_phase
            record["resume_target"] = blocking_phase
        else:
            record["block_reason"] = ""
        record["merge_ready"] = self._compute_merge_ready(record)
        record["updated_at"] = _utc_now()

    @staticmethod
    def _status_for_phase(phase: str) -> str:
        if phase == PHASE_COMPLETE:
            return STATUS_COMPLETE
        if phase == PHASE_FAILED:
            return STATUS_FAILED
        if phase == PHASE_READY:
            return STATUS_READY
        if phase == PHASE_BLOCKED:
            return STATUS_BLOCKED
        return STATUS_ACTIVE

    @staticmethod
    def _compute_merge_ready(record: dict) -> bool:
        return (
            record["phase"] in {PHASE_READY, PHASE_COMPLETE}
            and record["blocker_count"] == 0
            and record["major_count"] == 0
        )

    # -- record review (Codex MCP, runner receipt) ----------------------------
    def record_review(self, actor: str, job_id: str, payload: dict) -> dict:
        if actor != ACTOR_CODEX:
            raise AdapterError(
                "ROLE_VIOLATION", "only Codex MCP may record a review"
            )
        try:
            request = ReviewRecordRequest.model_validate(payload)
        except ValidationError as exc:
            raise AdapterError("INVALID_REQUEST", "review submission is invalid") from exc
        authority = self._require_authority()
        try:
            receipt = authority.verify_review(request.receipt)
        except (ValidationError, KeyError) as exc:
            raise AdapterError("INVALID_REQUEST", "review runner receipt is invalid") from exc

        payload_sha256 = canonical_sha256(payload)
        event_kind = (
            AUDIT_REVIEW_INCOMPLETE
            if not self._receipt_complete(receipt)
            else AUDIT_REVIEW_RECORDED
        )

        # Idempotent replay BEFORE any mutable-state or challenge check.
        replay = self.store.replay(
            request.op_id,
            principal=actor,
            job_id=job_id,
            kind=event_kind,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay

        record = self._load(job_id)
        if record["phase"] != PHASE_REVIEWING or record["active_worker"] != ACTOR_CODEX:
            raise AdapterError(
                "ROLE_VIOLATION", "reviews may only be recorded while REVIEWING"
            )
        challenge = self._active_challenge(job_id, CHALLENGE_KIND_REVIEW)
        self._verify_review_binding(receipt, challenge, record)

        record["review_round"] += 1
        record["codex_thread_id"] = receipt.codex_thread_id
        record["codex_cli_version"] = receipt.codex_cli_version
        record["codex_audit"] = {
            "challenge_id": receipt.challenge_id,
            "receipt_id": receipt.receipt_id,
            "codex_modified_files": receipt.modified_files,
            "prompt_sha256": receipt.prompt_sha256,
            "response_sha256": receipt.response_sha256,
            "before_head": receipt.before_head,
            "after_head": receipt.after_head,
            "before_diff_hash": receipt.before_diff_hash,
            "after_diff_hash": receipt.after_diff_hash,
            "allowed_paths": list(receipt.allowed_paths),
            "invocation": redact(receipt.invocation.model_dump(mode="json")),
            "snapshot_verified": True,
        }
        counts = _count_receipt_findings(receipt.findings)
        record["blocker_count"] = counts["blocker"]
        record["major_count"] = counts["major"]
        record["minor_count"] = counts["minor"]
        record["findings"] = [
            {
                "severity": f.severity,
                "title": f.title,
                "path": f.path,
                "detail": f.detail,
                "raised_by": ACTOR_CODEX,
            }
            for f in receipt.findings
        ]

        complete = self._receipt_complete(receipt)
        challenge_issue = None
        if not complete:
            target = PHASE_BLOCKED
            record["phase"] = target
            record["status"] = STATUS_REVIEW_INCOMPLETE
            record["active_worker"] = None
            record["block_reason"] = "review run was not clean and complete"
            record["next_action"] = "re-run review with a clean, complete audit"
            record["blocking_phase"] = PHASE_REVIEWING
            record["resume_target"] = PHASE_REVIEWING
            record["merge_ready"] = False
            record["updated_at"] = _utc_now()
            event_payload = {
                "codex_modified_files": receipt.modified_files,
                "receipt_id": receipt.receipt_id,
                "challenge_id": receipt.challenge_id,
            }
        elif record["blocker_count"] > 0 or record["major_count"] > 0:
            target = PHASE_FIXING
            record["phase"] = target
            record["active_worker"] = PHASE_OWNER[target]
            record["status"] = STATUS_ACTIVE
            record["block_reason"] = ""
            record["next_action"] = "address blocker/major findings, then re-review"
            record["merge_ready"] = False
            record["updated_at"] = _utc_now()
            event_payload = {
                "routed_to": target,
                "blocker_count": record["blocker_count"],
                "major_count": record["major_count"],
                "receipt_id": receipt.receipt_id,
                "challenge_id": receipt.challenge_id,
            }
        else:
            target = PHASE_VERIFYING
            record["phase"] = target
            record["active_worker"] = PHASE_OWNER[target]
            record["status"] = STATUS_ACTIVE
            record["block_reason"] = ""
            record["next_action"] = "run independent Hermes verification"
            record["merge_ready"] = False
            record["updated_at"] = _utc_now()
            challenge_issue = self._issue_verification_challenge(record)
            event_payload = {
                "routed_to": target,
                "blocker_count": record["blocker_count"],
                "major_count": record["major_count"],
                "receipt_id": receipt.receipt_id,
                "challenge_id": receipt.challenge_id,
            }

        operation_result = dict(record)
        if challenge_issue is not None:
            operation_result["verification_challenge"] = challenge_issue
        stored = self.store.transition(
            job_id,
            expected_phase=PHASE_REVIEWING,
            expected_revision=self.store.get_revision(job_id),
            record=record,
            event_kind=event_kind,
            event_payload=event_payload,
            op_id=request.op_id,
            payload_sha256=payload_sha256,
            op_principal=actor,
            challenge_consume=challenge,
            challenge_issue=challenge_issue,
            review_receipt=request.receipt,
            operation_result=operation_result,
        )
        response = dict(stored)
        if challenge_issue is not None:
            response["verification_challenge"] = challenge_issue
        return response

    @staticmethod
    def _receipt_complete(receipt: ReviewRunnerReceipt) -> bool:
        return (
            receipt.modified_files == 0
            and receipt.before_head == receipt.after_head
            and receipt.before_diff_hash == receipt.after_diff_hash
        )

    def _verify_review_binding(
        self,
        receipt: ReviewRunnerReceipt,
        challenge: dict,
        record: dict,
    ) -> None:
        if receipt.challenge_id != challenge["challenge_id"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "review receipt is bound to a different challenge"
            )
        if receipt.challenge_nonce != challenge["nonce"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "review receipt nonce does not match the challenge"
            )
        if receipt.job_id != challenge["job_id"] or receipt.job_id != record["job_id"]:
            raise AdapterError("CHALLENGE_MISMATCH", "review receipt is bound to another job")
        if receipt.kind != CHALLENGE_KIND_REVIEW:
            raise AdapterError("CHALLENGE_MISMATCH", "review receipt kind mismatch")
        if receipt.principal != ACTOR_CODEX:
            raise AdapterError("ROLE_VIOLATION", "review receipt is bound to another principal")
        if receipt.review_round != challenge["review_round"]:
            raise AdapterError("CHALLENGE_MISMATCH", "review receipt is for a different round")
        if receipt.prompt_sha256 != challenge["prompt_sha256"]:
            raise AdapterError("CHALLENGE_MISMATCH", "review receipt prompt hash mismatch")
        if (
            receipt.before_head != challenge["current_head"]
            or receipt.after_head != challenge["current_head"]
            or receipt.before_diff_hash != challenge["current_diff_hash"]
            or receipt.after_diff_hash != challenge["current_diff_hash"]
            or list(receipt.allowed_paths) != list(challenge["allowed_paths"])
        ):
            raise AdapterError(
                "CHALLENGE_MISMATCH", "review receipt is not bound to the challenge snapshot"
            )
        self._assert_challenge_snapshot(challenge, record)

    # -- record verification (Hermes, validator receipt) ----------------------
    def record_verification(self, actor: str, job_id: str, payload: dict) -> dict:
        if actor != ACTOR_HERMES:
            raise AdapterError(
                "ROLE_VIOLATION", "only Hermes may record verification"
            )
        try:
            request = VerificationRecordRequest.model_validate(payload)
        except ValidationError as exc:
            raise AdapterError("INVALID_REQUEST", "verification submission is invalid") from exc
        authority = self._require_authority()
        try:
            receipt = authority.verify_validation(request.receipt)
        except (ValidationError, KeyError) as exc:
            raise AdapterError(
                "INVALID_REQUEST", "validation runner receipt is invalid"
            ) from exc

        # Recompute the evidence digest and cross-check pass/fail counts
        # against the check groups. This is where caller-authored counts and
        # evidence digests are rejected as non-authoritative.
        self._verify_validation_integrity(receipt)

        payload_sha256 = canonical_sha256(payload)
        gate_satisfied = (
            receipt.boundary_result == "PASSED"
            and receipt.fail_count == 0
            and request.focused_test.status == "PASSED"
            and request.full_test.status == "PASSED"
        )
        event_kind = (
            AUDIT_VERIFICATION_RECORDED
            if gate_satisfied
            else AUDIT_VERIFICATION_BLOCKED
        )

        replay = self.store.replay(
            request.op_id,
            principal=actor,
            job_id=job_id,
            kind=event_kind,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay

        record = self._load(job_id)
        self._require_owner(actor, record)
        if record["phase"] != PHASE_VERIFYING or record["active_worker"] != ACTOR_HERMES:
            raise AdapterError(
                "ROLE_VIOLATION", "verification may only be recorded while VERIFYING"
            )
        challenge = self._active_challenge(job_id, CHALLENGE_KIND_VERIFICATION)
        self._verify_verification_binding(receipt, challenge, record)

        record["last_focused_test"] = request.focused_test.model_dump(mode="json")
        record["last_full_test"] = request.full_test.model_dump(mode="json")
        record["verification_evidence"] = {
            "receipt_id": receipt.receipt_id,
            "challenge_id": receipt.challenge_id,
            "validator_id": receipt.validator_id,
            "validator_version": receipt.validator_version,
            "boundary_result": receipt.boundary_result,
            "pass_count": receipt.pass_count,
            "fail_count": receipt.fail_count,
            "snapshot_sha": receipt.snapshot_sha,
            "evidence_sha256": receipt.evidence_sha256,
        }

        if not gate_satisfied:
            record["phase"] = PHASE_BLOCKED
            record["status"] = STATUS_BLOCKED
            record["active_worker"] = None
            record["block_reason"] = _verification_block_reason(
                request, gate_satisfied, receipt
            )
            record["next_action"] = "fix failing verification evidence and re-verify"
            record["blocking_phase"] = PHASE_VERIFYING
            record["resume_target"] = PHASE_VERIFYING
            record["merge_ready"] = False
            record["updated_at"] = _utc_now()
            event_payload = {
                "focused": request.focused_test.status,
                "full": request.full_test.status,
                "boundary_result": receipt.boundary_result,
                "receipt_id": receipt.receipt_id,
                "challenge_id": receipt.challenge_id,
            }
        else:
            record["phase"] = PHASE_READY
            record["status"] = STATUS_READY
            record["active_worker"] = None
            record["block_reason"] = ""
            record["next_action"] = "await GPT/V4 validation"
            record["merge_ready"] = True
            record["updated_at"] = _utc_now()
            event_payload = {
                "merge_ready": True,
                "receipt_id": receipt.receipt_id,
                "challenge_id": receipt.challenge_id,
            }

        stored = self.store.transition(
            job_id,
            expected_phase=PHASE_VERIFYING,
            expected_revision=self.store.get_revision(job_id),
            record=record,
            event_kind=event_kind,
            event_payload=event_payload,
            op_id=request.op_id,
            payload_sha256=payload_sha256,
            op_principal=actor,
            challenge_consume=challenge,
            validation_receipt=request.receipt,
        )
        return dict(stored)

    @staticmethod
    def _verify_validation_integrity(receipt: ValidationRunnerReceipt) -> None:
        groups = [g.model_dump(mode="json") for g in receipt.check_groups]
        computed = hashlib.sha256(
            validation_evidence_material(
                check_groups=groups,
                pass_count=receipt.pass_count,
                fail_count=receipt.fail_count,
                boundary_result=receipt.boundary_result,
                snapshot_sha=receipt.snapshot_sha,
                current_diff_hash=receipt.current_diff_hash,
            )
        ).hexdigest()
        if computed != receipt.evidence_sha256:
            raise AdapterError(
                "RECEIPT_MISMATCH", "validation receipt evidence digest is inconsistent"
            )
        passed = sum(1 for g in receipt.check_groups if g.exit_status == 0)
        failed = sum(1 for g in receipt.check_groups if g.exit_status != 0)
        if receipt.pass_count != passed or receipt.fail_count != failed:
            raise AdapterError(
                "RECEIPT_MISMATCH",
                "validation receipt pass/fail counts do not match check groups",
            )
        required_failed = [
            g for g in receipt.check_groups if g.required and g.exit_status != 0
        ]
        if receipt.boundary_result == "PASSED" and (required_failed or receipt.fail_count != 0):
            raise AdapterError(
                "RECEIPT_MISMATCH", "validation receipt boundary result is inconsistent"
            )
        if receipt.boundary_result == "FAILED" and not required_failed and receipt.fail_count == 0:
            raise AdapterError(
                "RECEIPT_MISMATCH", "validation receipt boundary result is inconsistent"
            )

    def _verify_verification_binding(
        self,
        receipt: ValidationRunnerReceipt,
        challenge: dict,
        record: dict,
    ) -> None:
        if receipt.challenge_id != challenge["challenge_id"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "validation receipt is bound to a different challenge"
            )
        if receipt.challenge_nonce != challenge["nonce"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "validation receipt nonce does not match the challenge"
            )
        if receipt.job_id != challenge["job_id"] or receipt.job_id != record["job_id"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "validation receipt is bound to another job"
            )
        if receipt.kind != CHALLENGE_KIND_VERIFICATION:
            raise AdapterError("CHALLENGE_MISMATCH", "validation receipt kind mismatch")
        if receipt.review_round != challenge["review_round"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH", "validation receipt is for a different round"
            )
        if (
            receipt.snapshot_sha != challenge["current_head"]
            or receipt.current_head != challenge["current_head"]
            or receipt.current_diff_hash != challenge["current_diff_hash"]
            or list(receipt.allowed_paths) != list(challenge["allowed_paths"])
        ):
            raise AdapterError(
                "CHALLENGE_MISMATCH",
                "validation receipt is not bound to the challenge snapshot",
            )
        self._assert_challenge_snapshot(challenge, record)

    # -- evidence capsule -----------------------------------------------------
    def evidence_capsule(self, actor: str, job_id: str) -> dict:
        record = self._load(job_id)
        self._require_owner(actor, record)
        receipt_evidence = self.store.evidence_material(job_id)
        capsule = {
            "schema_version": SCHEMA_VERSION,
            "capsule_type": "hermes.builder_review_evidence.v1",
            "job_id": record["job_id"],
            "phase": record["phase"],
            "status": record["status"],
            "merge_ready": record["merge_ready"],
            "store_security": {
                "guarantee": "local_consistency_and_single_artifact_rollback_detection",
                "detects": [
                    "database_only_rollback",
                    "anchor_only_rollback",
                    "missing_anchor",
                ],
                "excludes": "coordinated_rollback_of_database_anchor_and_signing_keys",
            },
            "repository": {
                "repository_id": record["repository_id"],
                "branch": record["branch"],
                "starting_sha": record["starting_sha"],
                "baseline_evidence": record["baseline_evidence"],
                "current_head": record["current_head"],
            },
            "anchors": {
                "allowed_paths": record["allowed_paths"],
                "architecture_anchors": record["architecture_anchors"],
                "acceptance_anchors": record["acceptance_anchors"],
            },
            "current_diff_hash": record["current_diff_hash"],
            "findings": {
                "blocker": record["blocker_count"],
                "major": record["major_count"],
                "minor": record["minor_count"],
            },
            "codex": {
                "thread_id": record["codex_thread_id"],
                "cli_version": record["codex_cli_version"],
            },
            "review": {
                "round": record["review_round"],
                "snapshot_verified": bool(record["codex_audit"].get("snapshot_verified")),
                "challenge_bound": bool(record["codex_audit"].get("challenge_id")),
            },
            "verification": record["verification_evidence"],
            "receipt_evidence": receipt_evidence,
            "tests": {
                "focused": _compact_test(record["last_focused_test"]),
                "full": _compact_test(record["last_full_test"]),
            },
            "block_reason": record["block_reason"],
            "next_action": record["next_action"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }
        capsule_sha256 = canonical_sha256(capsule)
        checkpoint_body = {
            "evidence_sha256": capsule_sha256,
            "job_id": job_id,
            "global_audit_head": receipt_evidence["global_audit_head"],
        }
        checkpoint = self._require_authority().sign_capsule_checkpoint(checkpoint_body)
        result = {
            **capsule,
            "durable_checkpoint": {**checkpoint_body, **checkpoint},
        }
        return {**result, "capsule_sha256": canonical_sha256(result)}


def _count_receipt_findings(findings: list[ReceiptFinding]) -> dict:
    blocker = sum(1 for f in findings if f.severity == "BLOCKER")
    major = sum(1 for f in findings if f.severity == "MAJOR")
    minor = sum(1 for f in findings if f.severity == "MINOR")
    return {"blocker": blocker, "major": major, "minor": minor}


def _verification_block_reason(
    submission: VerificationRecordRequest, gate_satisfied: bool, receipt: ValidationRunnerReceipt
) -> str:
    reasons = []
    if receipt.boundary_result != "PASSED" or receipt.fail_count != 0:
        reasons.append("validation receipt is not passing")
    if submission.focused_test.status != "PASSED":
        reasons.append(f"focused test {submission.focused_test.status}")
    if submission.full_test.status != "PASSED":
        reasons.append(f"full test {submission.full_test.status}")
    return "; ".join(reasons) or "verification gate not satisfied"


def _compact_test(test: dict | None) -> dict | None:
    if not test:
        return None
    return {
        "scope": test.get("scope"),
        "status": test.get("status"),
        "command": test.get("command"),
        "summary": test.get("summary"),
    }
