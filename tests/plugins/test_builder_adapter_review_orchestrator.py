"""Review-orchestration control plane: persistence, transitions, roles,
challenges, runner/validator receipts, audit integrity, and evidence-capsule
coverage.

Trust-boundary tests verify that:

* a review completes only through a runner-minted receipt bound to the exact
  active challenge and server-observed snapshot;
* verification completes only through a validator-minted receipt whose
  evidence digest and pass/fail counts are recomputed server-side;
* ordinary API principals cannot mint either receipt;
* challenges are single-use, sole-active, and atomically superseded;
* op-id idempotency is keyed by (principal, job_id, kind, op_id, payload);
* record/audit/challenge/receipt tampering is detected inside the mutation
  transaction; and
* the prior (1.0.0) schema migrates transactionally.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from plugins.builder_adapter.canonical import (
    canonical_json_bytes,
    canonical_sha256,
    signed_material,
)
from plugins.builder_adapter.client import BuilderAdapterClient, OperatorKey
from plugins.builder_adapter.errors import AdapterError
from plugins.builder_adapter.gitops import GitVerifier
from plugins.builder_adapter.review_orchestrator import (
    PHASE_BLOCKED,
    PHASE_COMPLETE,
    PHASE_FAILED,
    PHASE_FIXING,
    PHASE_IMPLEMENTING,
    PHASE_READY,
    PHASE_REVIEWING,
    PHASE_VERIFYING,
    ReviewOrchestrator,
    ReviewStore,
    SCHEMA_VERSION,
)
from plugins.builder_adapter.review_receipts import (
    CodexReviewBackend as _CodexReviewBackend,
    ReceiptAuthority,
    ReviewRunner,
    ValidationAttestor,
    compute_validation_evidence_sha256,
    new_receipt_id,
    redact,
    redact_secrets,
)
from plugins.builder_adapter.review_runtime import ReviewRuntime
from plugins.builder_adapter.service import BuilderAdapterService
from plugins.builder_adapter.store import DispatchStore


PROMPT = "c" * 64
REVIEW_SECRET = b"r" * 32
VALIDATION_SECRET = b"v" * 32
REPOSITORY_ID = "hermes-agent"
BRANCH = "feat/review"
ALLOWED_PATHS = ["plugins/builder_adapter/**"]


def _test_interpreter() -> Path:
    return Path(
        "/Library/Developer/CommandLineTools/usr/bin/python3"
        if sys.platform == "darwin"
        else sys.executable
    ).resolve()


def CodexReviewBackend(**kwargs):
    """Construct the real backend with the fixture script interpreter pinned."""
    kwargs.setdefault(
        "interpreter_sha256", hashlib.sha256(_test_interpreter().read_bytes()).hexdigest()
    )
    return _CodexReviewBackend(**kwargs)


# ── git worktree fixtures ───────────────────────────────────────────────────
def _run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/usr/bin/git", "--no-pager", *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )


def make_git_worktree(tmp_path: Path, *, change: bool = True) -> tuple[Path, str, str]:
    """Create a source repo, a clone, and a linked worktree on ``feat/review``
    with an implementation change under the allowed path."""
    base = tmp_path.resolve()
    source = base / "source"
    source.mkdir(parents=True)
    _run_git("init", "-q", str(source))
    _run_git("-C", str(source), "config", "user.email", "test@example.invalid")
    _run_git("-C", str(source), "config", "user.name", "Test")
    (source / "README.md").write_text("base\n")
    _run_git("-C", str(source), "add", "README.md")
    _run_git("-C", str(source), "commit", "-qm", "base")
    starting_sha = _run_git("-C", str(source), "rev-parse", "HEAD").stdout.strip()

    repo = base / "repo"
    _run_git("clone", "-q", "--no-hardlinks", str(source), str(repo))
    worktree = base / "wt"
    _run_git(
        "-C", str(repo), "worktree", "add", "-q", "-b", BRANCH, str(worktree), starting_sha
    )
    if change:
        impl = worktree / "plugins/builder_adapter/impl.py"
        impl.parent.mkdir(parents=True, exist_ok=True)
        impl.write_text("value = 1\n")
        _run_git("-C", str(worktree), "add", "plugins/builder_adapter/impl.py")
        _run_git("-C", str(worktree), "commit", "-qm", "implementation")
    return worktree, starting_sha, str(source)


def make_orchestrator(
    tmp_path: Path, *, change: bool = True
) -> tuple[ReviewOrchestrator, ReviewStore, ReceiptAuthority, Path, str, str]:
    worktree, starting_sha, remote = make_git_worktree(tmp_path, change=change)
    store = ReviewStore(tmp_path / "review.db")
    git = GitVerifier({REPOSITORY_ID: remote})
    authority = ReceiptAuthority(
        review_runner_secret=REVIEW_SECRET, validation_runner_secret=VALIDATION_SECRET
    )
    orch = ReviewOrchestrator(
        store,
        git=git,
        authority=authority,
        repository_roots=[tmp_path.resolve()],
    )
    return orch, store, authority, worktree, starting_sha, remote


def make_simple_orchestrator(tmp_path: Path) -> tuple[ReviewOrchestrator, ReviewStore]:
    store = ReviewStore(tmp_path / "review.db")
    return ReviewOrchestrator(store), store


def create_payload(worktree: Path, starting_sha: str, **overrides) -> dict:
    payload = {
        "job_id": str(uuid4()),
        "repository_id": REPOSITORY_ID,
        "worktree_path": str(worktree),
        "branch": BRANCH,
        "starting_sha": starting_sha,
        "allowed_paths": list(ALLOWED_PATHS),
        "architecture_anchors": ["plugins/builder_adapter/store.py"],
        "acceptance_anchors": ["builder-adapter plugin tests pass"],
    }
    payload.update(overrides)
    return payload


def drive_to_reviewing(orch: ReviewOrchestrator, job_id: str, *, prompt: str = PROMPT) -> dict:
    orch.transition("hermes", job_id, {"target_phase": PHASE_IMPLEMENTING})
    result = orch.transition(
        "hermes", job_id, {"target_phase": PHASE_REVIEWING, "prompt_sha256": prompt}
    )
    return result["review_challenge"]


def real_prompt(text: str = "review this change") -> tuple[str, str]:
    """A prompt plus its canonical SHA-256, for concrete-runner tests."""
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def drive_to_reviewing_with_prompt(
    orch: ReviewOrchestrator, job_id: str, prompt_text: str
) -> dict:
    _, prompt_sha256 = real_prompt(prompt_text)
    orch.transition("hermes", job_id, {"target_phase": PHASE_IMPLEMENTING})
    result = orch.transition(
        "hermes",
        job_id,
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": prompt_sha256},
    )
    return result["review_challenge"]


def make_codex_executable(
    tmp_path: Path,
    *,
    findings=None,
    response: str = "review complete",
    write_then_restore: str | None = None,
    extra_fields: dict | None = None,
) -> str:
    """Write a fake read-only Codex boundary executable and return its path.

    The executable accepts the backend's fixed ``review`` argv and consumes the
    review prompt on stdin, then emits the strict boundary JSON on stdout.
    ``write_then_restore`` names a repo-relative path the boundary writes and
    restores (changing its metadata); ``extra_fields`` smuggles forbidden keys
    into the stdout payload.
    """
    script = tmp_path / "codex-review"
    payload = {
        "thread_id": "thread-1",
        "response": response,
        "findings": findings or [],
    }
    if extra_fields:
        payload.update(extra_fields)
    lines = [
        f"#!{_test_interpreter()}",
        "import json, sys",
        "sys.stdin.read()",  # accept the review prompt the backend pipes in
        f"_payload = {payload!r}",
    ]
    if write_then_restore:
        lines += [
            f"_path = {write_then_restore!r}",
            "try:",
            "    _orig = open(_path, 'rb').read()",
            "    open(_path, 'wb').write(b'malicious\\n')",
            "    open(_path, 'wb').write(_orig)",
            "except OSError:",
            "    pass",
        ]
    lines.append("print(json.dumps(_payload))")
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def make_review_runner(
    tmp_path: Path, git, authority: ReceiptAuthority, **kwargs
) -> ReviewRunner:
    backend = CodexReviewBackend(
        executable=make_codex_executable(tmp_path, **kwargs),
        version="0.0.0-test",
        identity="codex_mcp",
    )
    return ReviewRunner(git, authority, backend)


def build_review_receipt(authority: ReceiptAuthority, challenge: dict, **overrides) -> dict:
    fields = {
        "receipt_id": new_receipt_id(),
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["nonce"],
        "job_id": challenge["job_id"],
        "kind": "review",
        "principal": "codex_mcp",
        "review_round": challenge["review_round"],
        "prompt_sha256": challenge["prompt_sha256"],
        "response_sha256": "d" * 64,
        "codex_thread_id": "thread-1",
        "codex_cli_version": "0.2.0",
        "modified_files": 0,
        "invocation": {
            "runner": "codex_mcp",
            "runner_version": "0.2.0",
            "sandbox": "read_only",
            "approval_policy": "never",
            "command": "codex review --read-only",
        },
        "before_head": challenge["current_head"],
        "after_head": challenge["current_head"],
        "before_diff_hash": challenge["current_diff_hash"],
        "after_diff_hash": challenge["current_diff_hash"],
        "allowed_paths": list(challenge["allowed_paths"]),
        "findings": [],
        "started_at": "2026-08-13T00:00:00Z",
        "finished_at": "2026-08-13T00:00:00Z",
    }
    fields.update(overrides)
    return authority.mint_review(fields)


def build_validation_receipt(
    authority: ReceiptAuthority, challenge: dict, *, check_groups=None, boundary="PASSED", **overrides
) -> dict:
    groups = check_groups or [
        {
            "command_id": "ruff",
            "check_group": "static",
            "exit_status": 0,
            "required": True,
            "evidence_sha256": None,
        },
        {
            "command_id": "pytest",
            "check_group": "tests",
            "exit_status": 0,
            "required": True,
            "evidence_sha256": None,
        },
    ]
    pass_count = sum(1 for g in groups if g["exit_status"] == 0)
    fail_count = sum(1 for g in groups if g["exit_status"] != 0)
    evidence = compute_validation_evidence_sha256(
        check_groups=groups,
        pass_count=pass_count,
        fail_count=fail_count,
        boundary_result=boundary,
        snapshot_sha=challenge["current_head"],
        current_diff_hash=challenge["current_diff_hash"],
    )
    fields = {
        "receipt_id": new_receipt_id(),
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["nonce"],
        "job_id": challenge["job_id"],
        "kind": "verification",
        "principal": "hermes",
        "review_round": challenge["review_round"],
        "snapshot_sha": challenge["current_head"],
        "current_head": challenge["current_head"],
        "current_diff_hash": challenge["current_diff_hash"],
        "allowed_paths": list(challenge["allowed_paths"]),
        "validator_id": "hermes.builder_review.validation",
        "validator_version": "1.0.0",
        "profile_id": "profile",
        "check_groups": groups,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "boundary_result": boundary,
        "evidence_sha256": evidence,
        "started_at": "2026-08-13T00:00:00Z",
        "finished_at": "2026-08-13T00:00:00Z",
    }
    fields.update(overrides)
    return authority.mint_validation(fields)


def passing_verification(receipt: dict, *, focused=None, full=None) -> dict:
    return {
        "receipt": receipt,
        "focused_test": focused
        or {
            "scope": "focused",
            "status": "PASSED",
            "command": "pytest -q test_one.py",
            "ran_at": "2026-08-13T00:00:00Z",
        },
        "full_test": full
        or {
            "scope": "full",
            "status": "PASSED",
            "command": "pytest tests/plugins/",
            "ran_at": "2026-08-13T00:00:00Z",
        },
    }


def drive_to_verifying(
    orch: ReviewOrchestrator, authority: ReceiptAuthority, job_id: str
) -> dict:
    review_challenge = drive_to_reviewing(orch, job_id)
    receipt = build_review_receipt(authority, review_challenge)
    result = orch.record_review("codex_mcp", job_id, {"receipt": receipt})
    assert result["phase"] == PHASE_VERIFYING
    return result["verification_challenge"]


class FakeValidation:
    def __init__(self, *, overall="PASSED", commands=None):
        self._overall = overall
        self._commands = commands or [
            {
                "command_id": "ruff",
                "exit_status": 0,
                "started_at": "2026-08-13T00:00:00Z",
                "finished_at": "2026-08-13T00:00:01Z",
                "stdout_sha256": "a" * 64,
            },
            {
                "command_id": "pytest",
                "exit_status": 0,
                "started_at": "2026-08-13T00:00:01Z",
                "finished_at": "2026-08-13T00:00:02Z",
                "stdout_sha256": "b" * 64,
            },
        ]

    def run(self, profile_id, worktree, expected_sha):
        return {"profile": profile_id, "commands": self._commands, "overall_status": self._overall}


PROFILES = {
    "profile": {
        "check_group": "validation",
        "commands": [
            {"command_id": "ruff", "required": True},
            {"command_id": "pytest", "required": True},
        ],
    }
}


# ═══════════════════════════════════════════════════════════════════════════
# Persistence / reload / idempotent resume
# ═══════════════════════════════════════════════════════════════════════════
def test_persist_and_reload_preserves_phase(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    orch, store = make_simple_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})

    reloaded = ReviewOrchestrator(ReviewStore(store.path))
    record = reloaded.get("hermes", payload["job_id"])
    assert record["phase"] == PHASE_IMPLEMENTING
    assert record["active_worker"] == "deepseek"
    assert record["starting_sha"] == starting_sha
    assert record["allowed_paths"] == list(ALLOWED_PATHS)
    assert record["owner_principal"] == "hermes"


def test_restart_resume_continues_from_persisted_phase_not_queued(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    drive_to_reviewing(orch, payload["job_id"])

    restarted = ReviewOrchestrator(ReviewStore(store.path))
    record = restarted.get("hermes", payload["job_id"])
    assert record["phase"] == PHASE_REVIEWING
    assert record["active_worker"] == "codex_mcp"


def test_create_is_idempotent_for_identical_payload(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    orch, _ = make_simple_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    first = orch.create("hermes", payload)
    second = orch.create("hermes", payload)
    assert first["job_id"] == second["job_id"]
    assert first["phase"] == second["phase"] == "QUEUED"


def test_create_rejects_same_job_id_with_different_payload(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    orch, _ = make_simple_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    conflicting = dict(payload, branch="feat/other")
    with pytest.raises(AdapterError) as raised:
        orch.create("hermes", conflicting)
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"


def test_record_hash_tampering_fails_closed_on_load(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    orch, store = make_simple_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "tampered"}', payload["job_id"]),
        )
    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "RECORD_INTEGRITY"


def test_unsupported_schema_version_fails_closed(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    orch, store = make_simple_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with sqlite3.connect(store.path) as conn:
        row = conn.execute(
            "SELECT record_json FROM review_jobs WHERE job_id=?", (payload["job_id"],)
        ).fetchone()
    record = json.loads(row[0])
    record["schema_version"] = "9.9.9"
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=?, record_sha256=? WHERE job_id=?",
            (
                json.dumps(record, sort_keys=True),
                hashlib.sha256(
                    json.dumps(record, sort_keys=True).encode()
                ).hexdigest(),
                payload["job_id"],
            ),
        )
    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "INVALID_STATE"


# ═══════════════════════════════════════════════════════════════════════════
# Transitions: legal / illegal / stale / terminal
# ═══════════════════════════════════════════════════════════════════════════
def test_happy_path_full_transition_chain(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    verification_challenge = drive_to_verifying(orch, authority, job_id)
    receipt = build_validation_receipt(authority, verification_challenge)
    orch.record_verification(
        "hermes", job_id, passing_verification(receipt)
    )
    assert orch.get("hermes", job_id)["phase"] == PHASE_READY
    orch.transition("hermes", job_id, {"target_phase": PHASE_COMPLETE})
    record = orch.get("hermes", job_id)
    assert record["phase"] == PHASE_COMPLETE
    assert record["status"] == "COMPLETE"
    assert record["merge_ready"] is True


def test_deepseek_first_rejects_skipping_to_review(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with pytest.raises(AdapterError) as raised:
        orch.transition(
            "hermes",
            payload["job_id"],
            {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
        )
    assert raised.value.code == "INVALID_TRANSITION"


def test_illegal_transitions_are_rejected(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    for target in (PHASE_VERIFYING, PHASE_READY, PHASE_FIXING):
        with pytest.raises(AdapterError) as raised:
            orch.transition("hermes", payload["job_id"], {"target_phase": target})
        assert raised.value.code == "INVALID_TRANSITION"


def test_transition_cannot_bypass_review_gate_into_verifying(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
    )
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_VERIFYING})
    assert raised.value.code == "INVALID_TRANSITION"


def test_stale_transition_with_wrong_expected_phase_is_rejected(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with pytest.raises(AdapterError) as raised:
        orch.transition(
            "hermes",
            payload["job_id"],
            {"target_phase": PHASE_IMPLEMENTING, "expected_phase": PHASE_REVIEWING},
        )
    assert raised.value.code == "STALE_TRANSITION"


def test_terminal_state_conflict_rejects_further_transitions(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": "FAILED"})
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    assert raised.value.code == "TERMINAL_STATE_CONFLICT"


def test_blocked_phase_can_resume_to_owned_phase(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    orch.transition(
        "hermes", payload["job_id"], {"target_phase": PHASE_BLOCKED, "block_reason": "hold"}
    )
    assert orch.get("hermes", payload["job_id"])["status"] == "BLOCKED"
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    assert orch.get("hermes", payload["job_id"])["phase"] == PHASE_IMPLEMENTING


def test_blocked_phase_can_always_fail_terminally_regardless_of_resume_target(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_BLOCKED, "block_reason": "cannot continue"},
    )

    failed = orch.transition(
        "hermes", payload["job_id"], {"target_phase": PHASE_FAILED}
    )

    assert failed["phase"] == PHASE_FAILED
    assert failed["status"] == "FAILED"


@pytest.mark.parametrize("challenge_kind", ["review", "verification"])
def test_challenge_reproves_baseline_ancestry_after_branch_reset(
    tmp_path, challenge_kind
):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    if challenge_kind == "review":
        drive_to_reviewing(orch, payload["job_id"])
    else:
        drive_to_verifying(orch, authority, payload["job_id"])
    tree = _run_git("-C", str(worktree), "rev-parse", "HEAD^{tree}").stdout.strip()
    orphan = _run_git(
        "-C",
        str(worktree),
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit-tree",
        tree,
        "-m",
        "unrelated root",
    ).stdout.strip()
    _run_git("-C", str(worktree), "reset", "--hard", orphan)

    with pytest.raises(AdapterError) as raised:
        if challenge_kind == "review":
            orch.review_challenge("hermes", payload["job_id"])
        else:
            orch.verification_challenge("hermes", payload["job_id"])

    assert raised.value.code == "HEAD_MISMATCH"


# ═══════════════════════════════════════════════════════════════════════════
# Role enforcement
# ═══════════════════════════════════════════════════════════════════════════
def test_create_requires_hermes(tmp_path):
    orch, _ = make_simple_orchestrator(tmp_path)
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    with pytest.raises(AdapterError) as raised:
        orch.create("deepseek", create_payload(worktree, starting_sha))
    assert raised.value.code == "ROLE_VIOLATION"


def test_transition_requires_hermes(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with pytest.raises(AdapterError) as raised:
        orch.transition("deepseek", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    assert raised.value.code == "ROLE_VIOLATION"


def test_review_requires_codex_mcp(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge)
    with pytest.raises(AdapterError) as raised:
        orch.record_review("hermes", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "ROLE_VIOLATION"


def test_review_rejected_outside_reviewing_phase(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge)
    # Consume the review to leave REVIEWING.
    orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    # After a clean review the phase has moved to VERIFYING; recording another
    # review is rejected because reviews only occur while REVIEWING.
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "ROLE_VIOLATION"


def test_verification_requires_hermes(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "codex_mcp", payload["job_id"], passing_verification(receipt)
        )
    assert raised.value.code == "ROLE_VIOLATION"


# ═══════════════════════════════════════════════════════════════════════════
# Review acceptance enforcement (runner-receipt bound)
# ═══════════════════════════════════════════════════════════════════════════
def test_codex_modified_files_blocks_review_and_does_not_advance(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge, modified_files=2)
    result = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert result["phase"] == PHASE_BLOCKED
    assert result["status"] == "REVIEW_INCOMPLETE"
    assert result["resume_target"] == PHASE_REVIEWING


def test_findings_loop_routes_blocker_to_fixing_then_back_to_reviewing(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])

    finding = {"severity": "MAJOR", "title": "missing guard", "path": "store.py"}
    receipt = build_review_receipt(authority, challenge, findings=[finding])
    after_first = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert after_first["phase"] == PHASE_FIXING
    assert after_first["active_worker"] == "deepseek"
    assert after_first["major_count"] == 1
    assert after_first["review_round"] == 1

    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
    )
    second_challenge = orch.review_challenge("hermes", payload["job_id"])
    second_receipt = build_review_receipt(authority, second_challenge)
    after_second = orch.record_review(
        "codex_mcp", payload["job_id"], {"receipt": second_receipt}
    )
    assert after_second["phase"] == PHASE_VERIFYING
    assert after_second["review_round"] == 2


def test_only_zero_blocker_and_major_advance_to_verifying(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    blockers = [
        {"severity": "BLOCKER", "title": "must fix"},
        {"severity": "MAJOR", "title": "must fix"},
    ]
    receipt = build_review_receipt(authority, challenge, findings=blockers)
    result = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert result["phase"] == PHASE_FIXING
    assert result["blocker_count"] == 1
    assert result["major_count"] == 1


def test_minor_only_findings_still_advance_to_verifying(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(
        authority, challenge, findings=[{"severity": "MINOR", "title": "nit"}]
    )
    result = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert result["phase"] == PHASE_VERIFYING
    assert result["minor_count"] == 1


def test_caller_cannot_impersonate_by_setting_actor_strings(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])

    for impostor in ("deepseek", "hermes"):
        receipt = build_review_receipt(authority, challenge)
        with pytest.raises(AdapterError) as raised:
            orch.record_review(impostor, payload["job_id"], {"receipt": receipt})
        assert raised.value.code == "ROLE_VIOLATION"

    receipt = build_review_receipt(
        authority,
        challenge,
        findings=[{"severity": "MINOR", "title": "nit"}],
    )
    result = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert result["phase"] == PHASE_VERIFYING
    assert result["findings"][0]["raised_by"] == "codex_mcp"


# ═══════════════════════════════════════════════════════════════════════════
# Verification gate (validator-receipt bound)
# ═══════════════════════════════════════════════════════════════════════════
def test_verification_gate_blocks_on_failed_focused_test(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    result = orch.record_verification(
        "hermes",
        payload["job_id"],
        passing_verification(
            receipt,
            focused={
                "scope": "focused",
                "status": "FAILED",
                "command": "pytest -q",
                "ran_at": "2026-08-13T00:00:00Z",
            },
        ),
    )
    assert result["phase"] == PHASE_BLOCKED
    assert result["status"] == "BLOCKED"
    assert "focused test FAILED" in result["block_reason"]
    assert result["resume_target"] == PHASE_VERIFYING


def test_verification_gate_records_evidence_before_ready(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    result = orch.record_verification(
        "hermes", payload["job_id"], passing_verification(receipt)
    )
    assert result["phase"] == PHASE_READY
    assert result["merge_ready"] is True
    assert result["last_focused_test"]["status"] == "PASSED"
    assert result["last_full_test"]["status"] == "PASSED"
    assert result["verification_evidence"]["receipt_id"] == receipt["receipt_id"]
    assert result["verification_evidence"]["boundary_result"] == "PASSED"


# ═══════════════════════════════════════════════════════════════════════════
# Deterministic evidence capsule
# ═══════════════════════════════════════════════════════════════════════════
def test_evidence_capsule_is_deterministic_and_self_describing(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    orch.record_verification("hermes", payload["job_id"], passing_verification(receipt))

    capsule = orch.evidence_capsule("hermes", payload["job_id"])
    again = orch.evidence_capsule("hermes", payload["job_id"])
    assert capsule == again
    expected = {key: capsule[key] for key in capsule if key != "capsule_sha256"}
    assert capsule["capsule_sha256"] == canonical_sha256(expected)
    assert capsule["store_security"] == {
        "guarantee": "local_consistency_and_single_artifact_rollback_detection",
        "detects": [
            "database_only_rollback",
            "anchor_only_rollback",
            "missing_anchor",
        ],
        "excludes": "coordinated_rollback_of_database_anchor_and_signing_keys",
    }


def test_evidence_capsule_requires_no_full_transcript(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    capsule = orch.evidence_capsule("hermes", payload["job_id"])
    assert "transcript" not in capsule
    assert set(capsule) >= {
        "job_id",
        "phase",
        "status",
        "anchors",
        "current_diff_hash",
        "findings",
        "tests",
        "codex",
        "block_reason",
        "next_action",
        "merge_ready",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Backwards compatibility with existing builder jobs
# ═══════════════════════════════════════════════════════════════════════════
def test_review_store_is_additive_and_leaves_dispatch_store_untouched(tmp_path):
    dispatch = DispatchStore(tmp_path / "journal.db")
    dispatch_id = "00000000-0000-0000-0000-000000000001"
    dispatch.reserve(dispatch_id, "k" * 32, "a" * 64, "CYCLE", "principal")
    review = ReviewStore(tmp_path / "review.db")

    with sqlite3.connect(dispatch.path) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "review_jobs" not in tables
    assert "dispatches" in tables

    with sqlite3.connect(review.path) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "review_jobs" in tables
    assert "review_meta" in tables
    assert "dispatches" not in tables


def test_list_filters_by_phase_and_status(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    first = orch.create("hermes", create_payload(worktree, starting_sha))
    second = orch.create("hermes", create_payload(worktree, starting_sha))
    orch.transition("hermes", first["job_id"], {"target_phase": PHASE_IMPLEMENTING})

    implementing = orch.list("hermes", phase=PHASE_IMPLEMENTING)["jobs"]
    queued = orch.list("hermes", phase="QUEUED")["jobs"]
    assert [j["job_id"] for j in implementing] == [first["job_id"]]
    assert [j["job_id"] for j in queued] == [second["job_id"]]
    assert len(orch.list("hermes")["jobs"]) == 2


# ═══════════════════════════════════════════════════════════════════════════
# Client / service surface
# ═══════════════════════════════════════════════════════════════════════════
def test_client_review_methods_build_and_sign_canonical_paths():
    seen = {}

    def transport(method, target, body, headers):
        seen.update(method=method, target=target, body=body, headers=headers)
        return 200, json.dumps({"phase": "QUEUED"}).encode()

    key = OperatorKey("operator-key", b"s" * 32)
    client = BuilderAdapterClient(
        Path("/tmp/adapter.sock"), key, clock=lambda: 1234, transport=transport
    )
    client.create_review_job({"job_id": "00000000-0000-4000-8000-000000000001"})
    assert seen["method"] == "POST"
    assert seen["target"] == "/v1/review-jobs"
    digest = hashlib.sha256(seen["body"]).hexdigest()
    expected = hmac.new(
        key.secret,
        signed_material(
            "POST",
            "/v1/review-jobs",
            "1234",
            seen["headers"]["X-Hermes-Nonce"],
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    assert seen["headers"]["X-Hermes-Signature"] == expected

    seen.clear()
    client.review_evidence_capsule("00000000-0000-4000-8000-000000000001")
    assert seen["target"] == (
        "/v1/review-jobs/00000000-0000-4000-8000-000000000001/evidence-capsule"
    )


def test_service_registers_review_routes_and_fails_closed_without_orchestrator():
    service = BuilderAdapterService(object(), object(), peer_resolver=lambda _: (0, 0))
    app = service.application()
    paths = {
        item.resource.canonical
        for item in app.router.routes()
        if item.resource is not None
    }
    assert "/v1/review-jobs" in paths
    assert "/v1/review-jobs/{job_id}" in paths
    assert "/v1/review-jobs/{job_id}/transition" in paths
    assert "/v1/review-jobs/{job_id}/review" in paths
    assert "/v1/review-jobs/{job_id}/verification" in paths
    # The public self-certification receipt route is gone.
    assert "/v1/review-jobs/{job_id}/verification-receipt" not in paths
    assert "/v1/review-jobs/{job_id}/review-challenge" in paths
    assert "/v1/review-jobs/{job_id}/verification-challenge" in paths
    assert "/v1/review-jobs/{job_id}/evidence-capsule" in paths
    with pytest.raises(AdapterError) as raised:
        service._require_orchestrator()
    assert raised.value.code == "CAPABILITY_UNAVAILABLE"


def test_client_list_signs_full_path_including_query():
    seen = {}

    def transport(method, target, body, headers):
        seen.update(method=method, target=target, body=body, headers=headers)
        return 200, json.dumps({"jobs": []}).encode()

    key = OperatorKey("operator-key", b"s" * 32)
    client = BuilderAdapterClient(
        Path("/tmp/adapter.sock"), key, clock=lambda: 1234, transport=transport
    )
    client.list_review_jobs(phase="REVIEWING", status="ACTIVE")
    assert seen["target"] == "/v1/review-jobs?phase=REVIEWING&status=ACTIVE"
    digest = hashlib.sha256(b"").hexdigest()
    expected = hmac.new(
        key.secret,
        signed_material(
            "GET",
            seen["target"],
            "1234",
            seen["headers"]["X-Hermes-Nonce"],
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    assert seen["headers"]["X-Hermes-Signature"] == expected


def test_read_routes_enforce_ownership(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]

    assert orch.get("hermes", job_id)["job_id"] == job_id
    with pytest.raises(AdapterError) as raised:
        orch.get("deepseek", job_id)
    assert raised.value.code == "AUTHORIZATION_FAILED"
    assert orch.list("deepseek")["jobs"] == []
    assert [j["job_id"] for j in orch.list("hermes")["jobs"]] == [job_id]
    with pytest.raises(AdapterError) as raised:
        orch.evidence_capsule("deepseek", job_id)
    assert raised.value.code == "AUTHORIZATION_FAILED"


# ═══════════════════════════════════════════════════════════════════════════
# BLOCKER 1: blocked-review cannot jump to verification
# ═══════════════════════════════════════════════════════════════════════════
def test_blocked_review_cannot_jump_to_verification(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge, modified_files=3)
    blocked = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert blocked["phase"] == PHASE_BLOCKED
    assert blocked["resume_target"] == PHASE_REVIEWING

    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_VERIFYING})
    assert raised.value.code == "INVALID_TRANSITION"

    resumed = orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
    )
    assert resumed["review_challenge"]["challenge_id"] != challenge["challenge_id"]


def test_failed_verification_cannot_resume_to_review_or_ready(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    blocked = orch.record_verification(
        "hermes",
        payload["job_id"],
        passing_verification(
            receipt,
            full={
                "scope": "full",
                "status": "FAILED",
                "command": "pytest",
                "ran_at": "2026-08-13T00:00:00Z",
            },
        ),
    )
    assert blocked["phase"] == PHASE_BLOCKED
    assert blocked["resume_target"] == PHASE_VERIFYING

    for target in (PHASE_REVIEWING, PHASE_READY):
        with pytest.raises(AdapterError) as raised:
            orch.transition("hermes", payload["job_id"], {"target_phase": target})
        assert raised.value.code == "INVALID_TRANSITION"

    resumed = orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_VERIFYING})
    assert resumed["verification_challenge"]["challenge_id"] != verification_challenge["challenge_id"]


# ═══════════════════════════════════════════════════════════════════════════
# BLOCKER 2: snapshot-bound, expiring, single-use challenge
# ═══════════════════════════════════════════════════════════════════════════
def test_review_challenge_is_snapshot_bound(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    assert challenge["kind"] == "review"
    assert challenge["job_id"] == payload["job_id"]
    assert challenge["repository_id"] == REPOSITORY_ID
    assert challenge["worktree_path"] == str(worktree)
    assert challenge["branch"] == BRANCH
    assert challenge["starting_sha"] == starting_sha
    committed_head = _run_git("-C", str(worktree), "rev-parse", "HEAD").stdout.strip()
    assert challenge["current_head"] == committed_head
    assert committed_head != starting_sha
    assert challenge["current_diff_hash"]
    assert challenge["allowed_paths"] == list(ALLOWED_PATHS)
    assert challenge["review_round"] == 1
    assert challenge["prompt_sha256"] == PROMPT
    assert challenge["principal"] == "codex_mcp"
    assert challenge["nonce"]
    assert challenge["expires_at"] > challenge["issued_at"]


def test_review_challenge_expires(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    store.challenge_ttl_seconds = -1
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge)
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "CHALLENGE_EXPIRED"


def test_review_challenge_is_single_use_and_rejects_replay(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge, modified_files=2)
    blocked = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert blocked["phase"] == PHASE_BLOCKED
    resumed = orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
    )
    assert resumed["review_challenge"]["challenge_id"] != challenge["challenge_id"]
    # Replaying the consumed challenge's receipt is rejected: it is now bound
    # to a superseded challenge, not the fresh active one.
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "CHALLENGE_MISMATCH"


# ═══════════════════════════════════════════════════════════════════════════
# BLOCKER 2 (this round): exact-active-challenge binding + decoy/cross checks
# ═══════════════════════════════════════════════════════════════════════════
def test_decoy_challenge_id_rejected_while_real_challenge_active(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    # A receipt minted for a different (decoy) challenge id.
    decoy = build_review_receipt(authority, challenge, challenge_id="d" * 64)
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": decoy})
    assert raised.value.code == "CHALLENGE_MISMATCH"
    # The real challenge remains active and consumable.
    good = build_review_receipt(authority, challenge)
    assert orch.record_review("codex_mcp", payload["job_id"], {"receipt": good})["phase"] == PHASE_VERIFYING


def test_cross_job_challenge_consumption_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    first = create_payload(worktree, starting_sha)
    second = create_payload(worktree, starting_sha)
    orch.create("hermes", first)
    orch.create("hermes", second)
    challenge = drive_to_reviewing(orch, first["job_id"])
    # Receipt minted for job A's challenge but submitted against job B.
    receipt = build_review_receipt(authority, challenge, job_id=second["job_id"])
    drive_to_reviewing(orch, second["job_id"])
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", second["job_id"], {"receipt": receipt})
    assert raised.value.code == "CHALLENGE_MISMATCH"


def test_cross_kind_challenge_consumption_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    review_challenge = drive_to_reviewing(orch, payload["job_id"])
    # A review receipt submitted as verification evidence.
    receipt = build_review_receipt(authority, review_challenge)
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "hermes",
            payload["job_id"],
            passing_verification(receipt),
        )
    assert raised.value.code in {"INVALID_REQUEST", "CHALLENGE_MISMATCH"}


def test_cross_principal_challenge_consumption_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(authority, challenge)
    # A non-codex actor cannot consume the codex-bound review challenge.
    with pytest.raises(AdapterError) as raised:
        orch.record_review("deepseek", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "ROLE_VIOLATION"
    # The rejected attempt must not consume the real active challenge.
    good = build_review_receipt(authority, challenge)
    assert orch.record_review("codex_mcp", payload["job_id"], {"receipt": good})["phase"] == PHASE_VERIFYING


def test_multiple_active_challenge_issuance_supersedes_older(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    first = drive_to_reviewing(orch, payload["job_id"])

    # Block the review without consuming its challenge: the first challenge
    # remains ACTIVE.
    orch.transition(
        "hermes", payload["job_id"], {"target_phase": PHASE_BLOCKED, "block_reason": "hold"}
    )
    # Resuming issues a fresh challenge that must atomically supersede the
    # still-active first one.
    resumed = orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
    )
    second = resumed["review_challenge"]

    with sqlite3.connect(store.path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT status FROM review_challenges WHERE job_id=? AND kind='review' "
            "ORDER BY issued_at",
            (payload["job_id"],),
        ).fetchall()
    statuses = [row["status"] for row in rows]
    assert statuses == ["REVOKED", "ACTIVE"]
    # At most one consumable active challenge remains.
    with sqlite3.connect(store.path) as conn:
        active = conn.execute(
            "SELECT COUNT(*) FROM review_challenges WHERE job_id=? AND kind='review' AND status='ACTIVE'",
            (payload["job_id"],),
        ).fetchone()
    assert active[0] == 1
    # The superseded first challenge cannot be consumed.
    with pytest.raises(AdapterError) as raised:
        orch.record_review(
            "codex_mcp",
            payload["job_id"],
            {"receipt": build_review_receipt(authority, first)},
        )
    assert raised.value.code in {"CHALLENGE_REPLAY", "CHALLENGE_MISMATCH"}


def test_repository_mutation_detected_independently(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    # Mutate the worktree after the challenge snapshot was observed.
    (worktree / "plugins/builder_adapter/impl.py").write_text("value = 2\n")

    # The runner boundary independently observes the current repository state
    # and refuses to mint any receipt for mutable, uncommitted content.
    git = GitVerifier({REPOSITORY_ID: remote})
    runner = make_review_runner(
        tmp_path, git, ReceiptAuthority(review_runner_secret=REVIEW_SECRET)
    )
    with pytest.raises(AdapterError) as raised:
        runner.run(challenge=challenge, prompt=prompt_text)
    assert raised.value.code == "WORKTREE_MISMATCH"


# ═══════════════════════════════════════════════════════════════════════════
# BLOCKER 3: privilege-separated receipts
# ═══════════════════════════════════════════════════════════════════════════
def test_ordinary_principal_cannot_mint_review_receipt(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])

    # An attacker without the runner secret forges the receipt body and a
    # guessed proof; the orchestrator rejects the authenticity proof.
    forged = {
        "receipt_id": new_receipt_id(),
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["nonce"],
        "job_id": payload["job_id"],
        "kind": "review",
        "principal": "codex_mcp",
        "review_round": challenge["review_round"],
        "prompt_sha256": challenge["prompt_sha256"],
        "response_sha256": "d" * 64,
        "codex_thread_id": "thread-1",
        "codex_cli_version": "0.2.0",
        "modified_files": 0,
        "invocation": {"runner": "codex_mcp", "runner_version": "0.2.0", "command": "x"},
        "before_head": challenge["current_head"],
        "after_head": challenge["current_head"],
        "before_diff_hash": challenge["current_diff_hash"],
        "after_diff_hash": challenge["current_diff_hash"],
        "allowed_paths": challenge["allowed_paths"],
        "findings": [],
        "started_at": "2026-08-13T00:00:00Z",
        "finished_at": "2026-08-13T00:00:00Z",
        "proof": "0" * 64,
    }
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": forged})
    assert raised.value.code == "RECEIPT_AUTHENTICITY_FAILED"


def test_ordinary_principal_cannot_mint_validation_receipt(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])

    # Build a structurally-valid receipt but sign it with the WRONG secret
    # (what an ordinary Hermes principal could do — they do not hold the
    # validator secret).
    fields = {
        "receipt_id": new_receipt_id(),
        "challenge_id": verification_challenge["challenge_id"],
        "challenge_nonce": verification_challenge["nonce"],
        "job_id": payload["job_id"],
        "kind": "verification",
        "principal": "hermes",
        "review_round": verification_challenge["review_round"],
        "snapshot_sha": verification_challenge["current_head"],
        "current_head": verification_challenge["current_head"],
        "current_diff_hash": verification_challenge["current_diff_hash"],
        "allowed_paths": verification_challenge["allowed_paths"],
        "validator_id": "hermes.builder_review.validation",
        "validator_version": "1.0.0",
        "profile_id": "profile",
        "check_groups": [
            {"command_id": "ruff", "check_group": "static", "exit_status": 0, "required": True, "evidence_sha256": None}
        ],
        "pass_count": 1,
        "fail_count": 0,
        "boundary_result": "PASSED",
        "evidence_sha256": "0" * 64,
        "started_at": "2026-08-13T00:00:00Z",
        "finished_at": "2026-08-13T00:00:00Z",
        "proof": "0" * 64,
    }
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "hermes", payload["job_id"], passing_verification(fields)
        )
    assert raised.value.code == "RECEIPT_AUTHENTICITY_FAILED"


def test_real_runner_integration_receipt_succeeds(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    git = GitVerifier({REPOSITORY_ID: remote})
    runner_authority = ReceiptAuthority(review_runner_secret=REVIEW_SECRET)
    runner = make_review_runner(tmp_path, git, runner_authority)

    receipt = runner.run(challenge=challenge, prompt=prompt_text)
    result = orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert result["phase"] == PHASE_VERIFYING
    # The runner owns the invocation identity and the modified-file proof; the
    # backend's claims never enter the receipt as callback fields.
    assert receipt["modified_files"] == 0
    assert receipt["invocation"]["sandbox"] == "read_only"
    assert receipt["invocation"]["approval_policy"] == "never"
    assert receipt["invocation"]["runner"] == "codex_mcp"
    assert receipt["codex_cli_version"] == "0.0.0-test"


def test_real_validator_integration_receipt_succeeds(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)

    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    git = GitVerifier({REPOSITORY_ID: remote})
    # The validator boundary holds only the validation secret, never the
    # review secret; the orchestrator verifies against the same secret.
    validator_authority = ReceiptAuthority(validation_runner_secret=VALIDATION_SECRET)
    attestor = ValidationAttestor(git, validator_authority, FakeValidation(), PROFILES)
    receipt = attestor.run(challenge=verification_challenge, profile_id="profile")

    result = orch.record_verification(
        "hermes", payload["job_id"], passing_verification(receipt)
    )
    assert result["phase"] == PHASE_READY
    assert result["merge_ready"] is True


def test_validator_runs_the_exact_committed_reviewed_head(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])

    class RecordingValidation(FakeValidation):
        expected_sha = None

        def run(self, profile_id, worktree, expected_sha):
            self.expected_sha = expected_sha
            return super().run(profile_id, worktree, expected_sha)

    validation = RecordingValidation()
    attestor = ValidationAttestor(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(validation_runner_secret=VALIDATION_SECRET),
        validation,
        PROFILES,
    )
    receipt = attestor.run(challenge=verification_challenge, profile_id="profile")
    committed_head = _run_git("-C", str(worktree), "rev-parse", "HEAD").stdout.strip()

    assert validation.expected_sha == committed_head
    assert receipt["snapshot_sha"] == committed_head
    assert verification_challenge["current_head"] == committed_head


def test_bad_evidence_digest_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(
        authority, verification_challenge, evidence_sha256="f" * 64
    )
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "hermes", payload["job_id"], passing_verification(receipt)
        )
    assert raised.value.code == "RECEIPT_MISMATCH"


def test_inconsistent_pass_fail_counts_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    # Two passing groups, but the receipt claims pass_count=7 fail_count=0.
    groups = [
        {"command_id": "ruff", "check_group": "static", "exit_status": 0, "required": True, "evidence_sha256": None},
        {"command_id": "pytest", "check_group": "tests", "exit_status": 0, "required": True, "evidence_sha256": None},
    ]
    evidence = compute_validation_evidence_sha256(
        check_groups=groups,
        pass_count=7,
        fail_count=0,
        boundary_result="PASSED",
        snapshot_sha=verification_challenge["current_head"],
        current_diff_hash=verification_challenge["current_diff_hash"],
    )
    receipt = build_validation_receipt(
        authority,
        verification_challenge,
        check_groups=groups,
        pass_count=7,
        fail_count=0,
        evidence_sha256=evidence,
    )
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "hermes", payload["job_id"], passing_verification(receipt)
        )
    assert raised.value.code == "RECEIPT_MISMATCH"


def test_receipt_replay_across_rounds_rejected(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    # Block the gate (failed focused test) to consume the challenge.
    blocked = orch.record_verification(
        "hermes",
        payload["job_id"],
        passing_verification(
            receipt,
            focused={"scope": "focused", "status": "FAILED", "command": "pytest -q", "ran_at": "2026-08-13T00:00:00Z"},
        ),
    )
    assert blocked["phase"] == PHASE_BLOCKED
    resumed = orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_VERIFYING})
    new_challenge = resumed["verification_challenge"]
    # Replaying the consumed receipt against the new round is rejected.
    with pytest.raises(AdapterError) as raised:
        orch.record_verification(
            "hermes", payload["job_id"], passing_verification(receipt)
        )
    assert raised.value.code in {"CHALLENGE_MISMATCH", "RECEIPT_REPLAY"}


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: op-id idempotency keyed by (principal, job_id, kind, op_id, payload)
# ═══════════════════════════════════════════════════════════════════════════
def test_exact_operation_retry_succeeds_after_consumption(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    request = passing_verification(receipt)
    request["op_id"] = "op-retry"

    first = orch.record_verification("hermes", payload["job_id"], request)
    assert first["phase"] == PHASE_READY
    # Exact retry (same op_id + payload) returns the original result even
    # though the challenge and receipt are now consumed.
    second = orch.record_verification("hermes", payload["job_id"], request)
    assert second["phase"] == PHASE_READY
    assert second["verification_evidence"]["receipt_id"] == receipt["receipt_id"]


def test_exact_ordinary_transition_retry_precedes_terminal_legality_checks(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    request = {"target_phase": PHASE_FAILED, "op_id": "op-terminal-retry"}

    first = orch.transition("hermes", payload["job_id"], request)
    second = orch.transition("hermes", payload["job_id"], request)

    assert second == first
    assert second["phase"] == PHASE_FAILED


def test_conflicting_ordinary_transition_reuse_fails_before_terminal_check(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_FAILED, "op_id": "op-terminal-conflict"},
    )

    with pytest.raises(AdapterError) as raised:
        orch.transition(
            "hermes",
            payload["job_id"],
            {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-terminal-conflict"},
        )
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"


def test_operation_result_tampering_fails_closed_on_replay(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    request = {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-tamper"}
    orch.transition("hermes", payload["job_id"], request)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_operations SET result_json=? WHERE op_id=?",
            ('{"job_id":"tampered"}', "op-tamper"),
        )

    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], request)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_operation_revision_tampering_fails_closed_on_load(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-revision-tamper"},
    )
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_operations SET revision=revision+1 WHERE op_id=?",
            ("op-revision-tamper",),
        )

    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_operation_deletion_is_detected_by_audit_binding(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition(
        "hermes",
        payload["job_id"],
        {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-delete-tamper"},
    )
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "DELETE FROM review_operations WHERE op_id=?", ("op-delete-tamper",)
        )

    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_cross_job_op_id_reuse_rejected(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    first = create_payload(worktree, starting_sha)
    second = create_payload(worktree, starting_sha)
    orch.create("hermes", first)
    orch.create("hermes", second)
    orch.transition("hermes", first["job_id"], {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-1"})
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", second["job_id"], {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-1"})
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"


def test_cross_kind_op_id_reuse_rejected(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-1"})
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_FAILED, "op_id": "op-1"})
    assert raised.value.code == "IDEMPOTENCY_CONFLICT"


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: monotonic revision + transactional audit verification
# ═══════════════════════════════════════════════════════════════════════════
def test_transactional_revision_is_monotonic_and_rejects_stale_cas(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    assert store.get_revision(job_id) == 0

    orch.transition("hermes", job_id, {"target_phase": PHASE_IMPLEMENTING})
    assert store.get_revision(job_id) == 1
    orch.transition("hermes", job_id, {"target_phase": PHASE_BLOCKED, "block_reason": "hold"})
    assert store.get_revision(job_id) == 2

    stale = store.get(job_id)
    stale["phase"] = PHASE_FAILED
    stale["status"] = "FAILED"
    stale["merge_ready"] = False
    with pytest.raises(AdapterError) as raised:
        store.transition(
            job_id,
            expected_phase=PHASE_BLOCKED,
            expected_revision=1,
            record=stale,
            event_kind="PHASE_TRANSITION",
            event_payload={"from": PHASE_BLOCKED, "to": PHASE_FAILED},
        )
    assert raised.value.code == "STALE_TRANSITION"
    assert store.get_revision(job_id) == 2
    assert store.get(job_id)["phase"] == PHASE_BLOCKED


def test_audit_chain_tampering_is_detected(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_audit SET payload_json=? WHERE job_id=? AND kind='JOB_CREATED'",
            ('{"tampered": true}', payload["job_id"]),
        )
    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_audit_previous_hash_linkage_tampering_is_detected(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_audit SET previous_hash=? WHERE sequence = (SELECT MAX(sequence) FROM review_audit)",
            ("0" * 64,),
        )
    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_challenge_tamper_between_load_and_mutation_detected(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    # Tamper the challenge JSON (status/hash drift) directly in the DB.
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_challenges SET challenge_json=? WHERE challenge_id=?",
            ('{"challenge_id": "tampered"}', challenge["challenge_id"]),
        )
    receipt = build_review_receipt(authority, challenge)
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_deleted_receipt_audit_event_detected(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    orch.record_verification("hermes", payload["job_id"], passing_verification(receipt))
    # Delete the receipt row (bypassing the immutable-delete trigger) so the
    # audit event references a missing receipt.
    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TRIGGER review_validation_receipts_immutable_delete")
        conn.execute(
            "DELETE FROM review_validation_receipts WHERE receipt_id=?",
            (receipt["receipt_id"],),
        )
    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])
    assert raised.value.code == "AUDIT_ROLLBACK"


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: snapshot freshness through COMPLETE
# ═══════════════════════════════════════════════════════════════════════════
def test_snapshot_drift_after_ready_rejects_complete(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    verification_challenge = drive_to_verifying(orch, authority, payload["job_id"])
    receipt = build_validation_receipt(authority, verification_challenge)
    orch.record_verification("hermes", payload["job_id"], passing_verification(receipt))
    assert orch.get("hermes", payload["job_id"])["phase"] == PHASE_READY

    # Drift the worktree after verification.
    (worktree / "plugins/builder_adapter/impl.py").write_text("value = 9\n")

    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_COMPLETE})
    assert raised.value.code == "WORKTREE_MISMATCH"


def test_dirty_allowed_content_cannot_receive_a_review_challenge(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    orch.transition("hermes", payload["job_id"], {"target_phase": PHASE_IMPLEMENTING})
    (worktree / "plugins/builder_adapter/impl.py").write_text("value = 99\n")

    with pytest.raises(AdapterError) as raised:
        orch.transition(
            "hermes",
            payload["job_id"],
            {"target_phase": PHASE_REVIEWING, "prompt_sha256": PROMPT},
        )

    assert raised.value.code == "WORKTREE_MISMATCH"
    assert orch.get("hermes", payload["job_id"])["phase"] == PHASE_IMPLEMENTING


def test_review_snapshot_hash_detects_chmod_only_drift(tmp_path):
    worktree, starting_sha, remote = make_git_worktree(tmp_path)
    verifier = GitVerifier({REPOSITORY_ID: remote})
    kwargs = {
        "repository_id": REPOSITORY_ID,
        "branch": BRANCH,
        "starting_sha": starting_sha,
        "allowed_paths": list(ALLOWED_PATHS),
        "allowed_roots": frozenset({tmp_path.resolve()}),
    }
    before = verifier.observe_review_snapshot(worktree, **kwargs)
    changed = worktree / "plugins/builder_adapter/impl.py"
    changed.chmod(0o755)
    _run_git("-C", str(worktree), "add", "plugins/builder_adapter/impl.py")
    _run_git("-C", str(worktree), "commit", "-qm", "change executable mode")
    after = verifier.observe_review_snapshot(worktree, **kwargs)

    assert after["diff_hash"] != before["diff_hash"]
    assert after["path_hashes"]["plugins/builder_adapter/impl.py"] != before[
        "path_hashes"
    ]["plugins/builder_adapter/impl.py"]


def test_review_snapshot_rejects_dangling_symlink_as_unsafe_type(tmp_path):
    worktree, starting_sha, remote = make_git_worktree(tmp_path, change=False)
    link = worktree / "plugins/builder_adapter/link.py"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to("missing-target.py")
    _run_git("-C", str(worktree), "add", "plugins/builder_adapter/link.py")
    _run_git("-C", str(worktree), "commit", "-qm", "add unsafe symlink")
    verifier = GitVerifier({REPOSITORY_ID: remote})

    with pytest.raises(AdapterError) as raised:
        verifier.observe_review_snapshot(
            worktree,
            repository_id=REPOSITORY_ID,
            branch=BRANCH,
            starting_sha=starting_sha,
            allowed_paths=list(ALLOWED_PATHS),
            allowed_roots=frozenset({tmp_path.resolve()}),
        )
    assert raised.value.code == "MANIFEST_MISMATCH"


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: path, secret, and schema hardening
# ═══════════════════════════════════════════════════════════════════════════
def test_path_traversal_and_nul_rejected(tmp_path):
    orch, _, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    with pytest.raises(AdapterError) as raised:
        orch.create("hermes", create_payload(worktree, starting_sha, worktree_path=str(worktree) + "\x00evil"))
    assert raised.value.code == "INVALID_REQUEST"


def _make_clean_baseline_orchestrator(tmp_path):
    worktree, starting_sha, remote = make_git_worktree(tmp_path, change=False)
    authority = ReceiptAuthority(
        review_runner_secret=REVIEW_SECRET,
        validation_runner_secret=VALIDATION_SECRET,
        capsule_checkpoint_secret=b"c" * 32,
    )
    store = ReviewStore(tmp_path / "review.db", authority=authority)
    orch = ReviewOrchestrator(
        store,
        git=GitVerifier({REPOSITORY_ID: remote}),
        authority=authority,
        repository_roots=[tmp_path.resolve()],
    )
    return orch, store, authority, worktree, starting_sha


def test_create_binds_server_observed_clean_branch_head(tmp_path):
    orch, _, _, worktree, starting_sha = _make_clean_baseline_orchestrator(tmp_path)
    result = orch.create("hermes", create_payload(worktree, starting_sha))

    assert result["starting_sha"] == starting_sha
    assert result["current_head"] == starting_sha
    assert result["baseline_evidence"]["starting_sha"] == starting_sha
    assert result["baseline_evidence"]["current_head"] == starting_sha
    assert result["baseline_evidence"]["source"] == "server_verified_hermes_baseline_ancestor"


def test_create_verifies_caller_baseline_is_ancestor_of_current_head(tmp_path):
    worktree, starting_sha, remote = make_git_worktree(tmp_path, change=True)
    authority = ReceiptAuthority(capsule_checkpoint_secret=b"c" * 32)
    orch = ReviewOrchestrator(
        ReviewStore(tmp_path / "review.db", authority=authority),
        git=GitVerifier({REPOSITORY_ID: remote}),
        authority=authority,
        repository_roots=[tmp_path.resolve()],
    )

    result = orch.create("hermes", create_payload(worktree, starting_sha))
    assert result["starting_sha"] == starting_sha
    assert result["baseline_evidence"]["starting_sha"] == starting_sha
    assert result["baseline_evidence"]["current_head"] != starting_sha


def test_signed_anchor_detects_offline_database_rewrite(tmp_path):
    orch, store, _, worktree, starting_sha = _make_clean_baseline_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET status='FAILED' WHERE job_id=?", (payload["job_id"],)
        )

    with pytest.raises(AdapterError) as raised:
        orch.get("hermes", payload["job_id"])

    assert raised.value.code == "AUDIT_ROLLBACK"


def test_record_review_replay_returns_original_verification_challenge(tmp_path):
    orch, _, authority, worktree, starting_sha = _make_clean_baseline_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    implementation = worktree / "plugins/builder_adapter/impl.py"
    implementation.parent.mkdir(parents=True, exist_ok=True)
    implementation.write_text("value = 1\n")
    _run_git("-C", str(worktree), "add", "plugins/builder_adapter/impl.py")
    _run_git("-C", str(worktree), "commit", "-qm", "implementation")
    challenge = drive_to_reviewing(orch, payload["job_id"])
    submission = {
        "op_id": str(uuid4()),
        "receipt": build_review_receipt(authority, challenge),
    }

    first = orch.record_review("codex_mcp", payload["job_id"], submission)
    replay = orch.record_review("codex_mcp", payload["job_id"], submission)

    assert replay["verification_challenge"] == first["verification_challenge"]
    with pytest.raises(AdapterError) as raised:
        orch.create("hermes", create_payload(worktree, starting_sha, worktree_path=str(worktree / ".." / ".." / "etc")))
    assert raised.value.code == "INVALID_REQUEST"


def test_worktree_outside_allowed_roots_rejected(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    store = ReviewStore(tmp_path / "review.db")
    authority = ReceiptAuthority(
        review_runner_secret=REVIEW_SECRET, validation_runner_secret=VALIDATION_SECRET
    )
    # Allowed root is a disjoint directory.
    other_root = tmp_path / "elsewhere"
    other_root.mkdir()
    orch = ReviewOrchestrator(
        store,
        authority=authority,
        repository_roots=[other_root],
    )
    with pytest.raises(AdapterError) as raised:
        orch.create("hermes", create_payload(worktree, starting_sha))
    assert raised.value.code == "WORKTREE_MISMATCH"


def test_secret_in_invocation_value_redacted(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    receipt = build_review_receipt(
        authority,
        challenge,
        invocation={
            "runner": "codex_mcp",
            "runner_version": "0.2.0",
            "sandbox": "read_only",
            "approval_policy": "never",
            "command": "codex review --token actual-secret-value",
        },
    )
    orch.record_review("codex_mcp", payload["job_id"], {"receipt": receipt})
    record = orch.get("hermes", payload["job_id"])
    assert "actual-secret-value" not in json.dumps(record["codex_audit"])
    assert "[REDACTED]" in json.dumps(record["codex_audit"])


def test_redact_helpers_scrub_value_level_secrets():
    assert redact({"command": "tool --token actual-secret"})["command"] == "tool --token [REDACTED]"
    auth = redact_secrets("Authorization: Bearer abc123")
    assert "abc123" not in auth and "[REDACTED]" in auth
    assert redact_secrets("password=hunter2") == "password=[REDACTED]"
    assert "hunter2" not in redact({"password": "hunter2"})["password"]


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: schema migration from the prior (1.0.0) schema
# ═══════════════════════════════════════════════════════════════════════════
def _create_prior_schema(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
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
            record_sha256 TEXT NOT NULL
        );
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
            nonce TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            consumed_at TEXT,
            consumed_op_id TEXT,
            challenge_json TEXT NOT NULL,
            challenge_sha256 TEXT NOT NULL
        );
        CREATE TABLE review_operations (
            op_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            result_json TEXT,
            revision INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE review_validation_receipts (
            receipt_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            snapshot_sha TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()
    path.chmod(0o600)


def test_prior_schema_migrates_transactionally(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    db = tmp_path / "review.db"
    _create_prior_schema(db)

    store = ReviewStore(db)
    with sqlite3.connect(store.path) as conn:
        conn.row_factory = sqlite3.Row
        meta = conn.execute("SELECT value FROM review_meta WHERE key='schema_version'").fetchone()
        assert meta[0] == SCHEMA_VERSION
        challenge_cols = {r["name"] for r in conn.execute("PRAGMA table_info(review_challenges)")}
        assert {"round", "prompt_sha256", "revoked_at", "superseded_by"} <= challenge_cols
        op_cols = {r["name"] for r in conn.execute("PRAGMA table_info(review_operations)")}
        assert {"principal", "result_sha256", "operation_sha256"} <= op_cols

    # A fresh job works on the migrated schema.
    # An unanchored legacy database may migrate for compatibility, but it may
    # not acquire a new checkpoint authority after initialization.  Exercise
    # the migrated schema without weakening that fail-closed boundary.
    orch = ReviewOrchestrator(store)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    assert orch.get("hermes", payload["job_id"])["phase"] == "QUEUED"


def test_previous_schema_operation_binding_migrates_transactionally(tmp_path):
    db = tmp_path / "review.db"
    ReviewStore(db)
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            ALTER TABLE review_operations RENAME TO review_operations_v12;
            CREATE TABLE review_operations (
                op_id TEXT PRIMARY KEY,
                principal TEXT NOT NULL,
                job_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                result_json TEXT,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                CHECK(length(payload_sha256) = 64)
            );
            DROP TABLE review_operations_v12;
            UPDATE review_meta SET value='1.1.0' WHERE key='schema_version';
            """
        )

    migrated = ReviewStore(db)
    with sqlite3.connect(migrated.path) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute(
            "SELECT value FROM review_meta WHERE key='schema_version'"
        ).fetchone()[0] == SCHEMA_VERSION
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(review_operations)")
        }
        assert {"result_sha256", "operation_sha256"} <= columns


def test_unsupported_schema_fails_closed(tmp_path):
    db = tmp_path / "review.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE review_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO review_meta(key, value) VALUES ('schema_version', '9.9.9')")
    conn.commit()
    conn.close()
    db.chmod(0o600)
    with pytest.raises(AdapterError) as raised:
        ReviewStore(db)
    assert raised.value.code == "UNSUPPORTED_SCHEMA"


# ═══════════════════════════════════════════════════════════════════════════
# Happy path requires clean review AND valid verification
# ═══════════════════════════════════════════════════════════════════════════
def test_ready_requires_clean_review_and_valid_verification(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]

    drive_to_reviewing(orch, job_id)
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", job_id, {"target_phase": PHASE_READY})
    assert raised.value.code == "INVALID_TRANSITION"

    review_challenge = orch.review_challenge("hermes", job_id)
    reviewed = orch.record_review(
        "codex_mcp",
        job_id,
        {"receipt": build_review_receipt(authority, review_challenge)},
    )
    assert reviewed["phase"] == PHASE_VERIFYING
    with pytest.raises(AdapterError) as raised:
        orch.transition("hermes", job_id, {"target_phase": PHASE_READY})
    assert raised.value.code == "INVALID_TRANSITION"

    verification_challenge = reviewed["verification_challenge"]
    receipt = build_validation_receipt(authority, verification_challenge)
    ready = orch.record_verification(
        "hermes", job_id, passing_verification(receipt)
    )
    assert ready["phase"] == PHASE_READY
    assert ready["merge_ready"] is True


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: review evidence is not callback-attested
# ═══════════════════════════════════════════════════════════════════════════
def test_malicious_boundary_cannot_inject_trusted_fields(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    # The boundary attempts to smuggle the exact fields the old callback owned.
    backend = CodexReviewBackend(
        executable=make_codex_executable(
            tmp_path,
            extra_fields={
                "modified_files": 0,
                "sandbox": "read_only",
                "identity": "codex_mcp",
                "invocation": {"runner": "codex_mcp"},
                "version": "0.0.0",
                "approval_policy": "never",
            },
        ),
        version="0.0.0-test",
        identity="codex_mcp",
    )
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        backend,
    )
    with pytest.raises(AdapterError) as raised:
        runner.run(challenge=challenge, prompt=prompt_text)
    assert raised.value.code == "ZERO_WRITE_UNPROVEN"


def test_write_and_restore_fails_closed(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    # The child makes no zero-write claim; the parent snapshot detects it.
    backend = CodexReviewBackend(
        executable=make_codex_executable(
            tmp_path, write_then_restore="plugins/builder_adapter/impl.py"
        ),
        version="0.0.0-test",
        identity="codex_mcp",
    )
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        backend,
    )
    with pytest.raises(AdapterError) as raised:
        runner.run(challenge=challenge, prompt=prompt_text)
    assert raised.value.code == "ZERO_WRITE_UNPROVEN"


def test_child_zero_write_claim_is_not_trusted(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    backend = CodexReviewBackend(
        executable=make_codex_executable(tmp_path, extra_fields={"zero_write": True}),
        version="0.0.0-test",
        identity="codex_mcp",
    )
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        backend,
    )
    with pytest.raises(AdapterError) as raised:
        runner.run(challenge=challenge, prompt=prompt_text)
    assert raised.value.code == "ZERO_WRITE_UNPROVEN"


def test_git_metadata_access_is_os_denied_without_mutation(tmp_path):
    orch, _, _, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    gitdir_marker = (worktree / ".git").read_text(encoding="utf-8").strip()
    gitdir = ((worktree / ".git").parent / gitdir_marker[8:]).resolve()
    protected_head = gitdir / "HEAD"
    before_bytes = protected_head.read_bytes()
    before_stat = protected_head.stat()
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)
    backend = CodexReviewBackend(
        executable=make_codex_executable(
            tmp_path, write_then_restore=str(protected_head)
        ),
        version="0.0.0-test",
        identity="codex_mcp",
    )
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        backend,
    )
    receipt = runner.run(challenge=challenge, prompt=prompt_text)
    after_stat = protected_head.stat()
    assert receipt["modified_files"] == 0
    assert protected_head.read_bytes() == before_bytes
    assert (after_stat.st_mtime_ns, after_stat.st_ctime_ns) == (
        before_stat.st_mtime_ns,
        before_stat.st_ctime_ns,
    )


def test_review_output_is_redacted_before_signing(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)
    secret = "super-secret-value"
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        authority,
        CodexReviewBackend(
            executable=make_codex_executable(
                tmp_path,
                response=f"Authorization: Bearer {secret}",
                findings=[
                    {
                        "severity": "MAJOR",
                        "title": f"token={secret}",
                        "path": f"reports/token={secret}.txt",
                        "detail": f"--api-key {secret}",
                    }
                ],
            ),
            version="0.0.0-test",
            identity="codex_mcp",
        ),
    )
    receipt = runner.run(challenge=challenge, prompt=prompt_text)
    serialized = json.dumps(receipt)
    assert secret not in serialized
    assert receipt["findings"][0]["title"] == "token=[REDACTED]"
    assert receipt["findings"][0]["path"] == "reports/token=[REDACTED]"
    assert receipt["findings"][0]["detail"] == "--api-key [REDACTED]"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"response": "x" * (64 * 1024 + 1)},
        {
            "findings": [
                {"severity": "MINOR", "title": f"finding-{index}"}
                for index in range(51)
            ]
        },
        {
            "findings": [
                {
                    "severity": "MINOR",
                    "title": f"finding-{index}",
                    "detail": "x" * 3000,
                }
                for index in range(50)
            ]
        },
        {
            "findings": [
                {"severity": "MAJOR", "title": "bad path", "path": "../secret"}
            ]
        },
    ],
)
def test_unbounded_or_unsafe_review_output_fails_closed(tmp_path, kwargs):
    orch, _, _, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        CodexReviewBackend(
            executable=make_codex_executable(tmp_path, **kwargs),
            version="0.0.0-test",
            identity="codex_mcp",
        ),
    )
    with pytest.raises(AdapterError):
        runner.run(challenge=challenge, prompt=prompt_text)


def test_concrete_backend_nonzero_exit_fails_closed(tmp_path):
    orch, _, authority, worktree, starting_sha, remote = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    prompt_text = "review this change"
    challenge = drive_to_reviewing_with_prompt(orch, payload["job_id"], prompt_text)

    script = tmp_path / "codex-fails"
    script.write_text(f"#!{_test_interpreter()}\nimport sys\nsys.exit(7)\n")
    script.chmod(0o755)
    backend = CodexReviewBackend(
        executable=str(script), version="0.0.0-test", identity="codex_mcp"
    )
    runner = ReviewRunner(
        GitVerifier({REPOSITORY_ID: remote}),
        ReceiptAuthority(review_runner_secret=REVIEW_SECRET),
        backend,
    )
    with pytest.raises(AdapterError) as raised:
        runner.run(challenge=challenge, prompt=prompt_text)
    assert raised.value.code == "CODEX_UNAVAILABLE"


def test_attestor_rejects_malformed_validation_result(tmp_path):
    git = object()

    class Malformed:
        def run(self, profile_id, worktree, expected_sha):
            return {"overall_status": "PASSED", "commands": []}

    attestor = ValidationAttestor(git, object(), Malformed(), PROFILES)
    with pytest.raises(AdapterError) as raised:
        attestor._validate_completed_result(
            {"overall_status": "PASSED", "commands": []}
        )
    assert raised.value.code == "VALIDATION_CONTAINMENT_UNAVAILABLE"


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: universal atomic integrity on every state-mutating path
# ═══════════════════════════════════════════════════════════════════════════
def test_tamper_then_exact_retry_fails_closed(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    orch.transition(
        "hermes", job_id, {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-1"}
    )
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "tampered"}', job_id),
        )
    with pytest.raises(AdapterError) as raised:
        orch.transition(
            "hermes", job_id, {"target_phase": PHASE_IMPLEMENTING, "op_id": "op-1"}
        )
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_record_review_tamper_then_exact_retry_fails_closed(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    challenge = drive_to_reviewing(orch, job_id)
    receipt = build_review_receipt(authority, challenge)
    request = {"receipt": receipt, "op_id": "op-review"}
    first = orch.record_review("codex_mcp", job_id, request)
    assert first["phase"] == PHASE_VERIFYING
    # Tamper the durable job record without recomputing its hash, then retry
    # the exact operation: replay must fail closed, never return stale success.
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "tampered"}', job_id),
        )
    with pytest.raises(AdapterError) as raised:
        orch.record_review("codex_mcp", job_id, request)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_record_verification_tamper_then_exact_retry_fails_closed(tmp_path):
    orch, store, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    verification_challenge = drive_to_verifying(orch, authority, job_id)
    receipt = build_validation_receipt(authority, verification_challenge)
    request = passing_verification(receipt)
    request["op_id"] = "op-verify"
    first = orch.record_verification("hermes", job_id, request)
    assert first["phase"] == PHASE_READY
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "tampered"}', job_id),
        )
    with pytest.raises(AdapterError) as raised:
        orch.record_verification("hermes", job_id, request)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_record_review_clean_exact_retry_succeeds(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    challenge = drive_to_reviewing(orch, job_id)
    receipt = build_review_receipt(authority, challenge)
    request = {"receipt": receipt, "op_id": "op-review-retry"}
    first = orch.record_review("codex_mcp", job_id, request)
    assert first["phase"] == PHASE_VERIFYING
    # An untampered exact retry after challenge/receipt consumption returns the
    # original result rather than re-executing the state transition.
    second = orch.record_review("codex_mcp", job_id, request)
    assert second["phase"] == PHASE_VERIFYING
    assert second["codex_audit"]["receipt_id"] == receipt["receipt_id"]


def test_issue_challenge_on_tampered_state_fails_closed(tmp_path):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "tampered"}', job_id),
        )
    challenge = {
        "challenge_id": "c" * 64,
        "job_id": job_id,
        "kind": "review",
        "principal": "codex_mcp",
        "review_round": 1,
        "nonce": "n" * 32,
        "prompt_sha256": PROMPT,
        "issued_at": "2026-08-13T00:00:00Z",
        "expires_at": "2026-08-13T01:00:00Z",
        "status": "ACTIVE",
    }
    with pytest.raises(AdapterError) as raised:
        store.issue_challenge(challenge)
    assert raised.value.code == "AUDIT_ROLLBACK"


def test_get_single_connection_verified_read(tmp_path, monkeypatch):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    job_id = payload["job_id"]

    connects = []
    original = ReviewStore._connect

    def counting_connect(self):
        connects.append(1)
        return original(self)

    monkeypatch.setattr(ReviewStore, "_connect", counting_connect)
    record = store.get(job_id)
    assert record["job_id"] == job_id
    assert len(connects) == 1


def test_list_single_connection_verified_read(tmp_path, monkeypatch):
    orch, store, _, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)

    connects = []
    original = ReviewStore._connect

    def counting_connect(self):
        connects.append(1)
        return original(self)

    monkeypatch.setattr(ReviewStore, "_connect", counting_connect)
    records = store.list()
    assert len(records) == 1
    assert len(connects) == 1


# ═══════════════════════════════════════════════════════════════════════════
# MAJOR: populated prior-schema migration
# ═══════════════════════════════════════════════════════════════════════════
def _prior_record_dict(worktree: Path, starting_sha: str, job_id: str) -> dict:
    return {
        "job_id": job_id,
        "schema_version": "1.0.0",
        "created_at": "2026-08-13T00:00:00Z",
        "updated_at": "2026-08-13T00:00:00Z",
        "repository_id": REPOSITORY_ID,
        "worktree_path": str(worktree),
        "branch": BRANCH,
        "starting_sha": starting_sha,
        "current_head": starting_sha,
        "current_diff_hash": "",
        "phase": "QUEUED",
        "status": "ACTIVE",
        "active_worker": None,
        "delegation_id": None,
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
        "allowed_paths": list(ALLOWED_PATHS),
        "architecture_anchors": ["plugins/builder_adapter/store.py"],
        "acceptance_anchors": ["builder-adapter plugin tests pass"],
        "blocking_phase": None,
        "resume_target": None,
        "owner_principal": "hermes",
    }


def _append_prior_audit(conn, *, event_id, job_id, kind, payload, created_at):
    redacted = redact(payload)
    previous = conn.execute(
        "SELECT event_hash FROM review_audit ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous[0] if previous else "0" * 64
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
        "INSERT INTO review_audit(event_id,job_id,kind,payload_json,created_at,"
        "previous_hash,event_hash) VALUES (?,?,?,?,?,?,?)",
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


def _populate_prior_store(db: Path, worktree: Path, starting_sha: str) -> str:
    _create_prior_schema(db)
    job_id = str(uuid4())
    record = _prior_record_dict(worktree, starting_sha, job_id)
    record_json = canonical_json_bytes(record).decode("utf-8")
    record_sha256 = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
    now = 1
    challenge_id = "c" * 64
    receipt_id = "rcpt-" + "1" * 48
    challenge = {
        "challenge_id": challenge_id,
        "job_id": job_id,
        "kind": "review",
        "principal": "codex_mcp",
        "nonce": "n" * 32,
        "issued_at": "2026-08-13T00:00:00Z",
        "expires_at": "2026-08-13T01:00:00Z",
        "status": "ACTIVE",
    }
    challenge_json = canonical_json_bytes(challenge).decode("utf-8")
    challenge_sha256 = hashlib.sha256(challenge_json.encode("utf-8")).hexdigest()
    receipt = {
        "receipt_id": receipt_id,
        "challenge_id": challenge_id,
        "job_id": job_id,
        "kind": "verification",
    }
    receipt_json = canonical_json_bytes(receipt).decode("utf-8")
    receipt_sha256 = hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO review_jobs(job_id,request_sha256,owner_principal,phase,"
            "status,revision,created_at,updated_at,record_json,record_sha256) "
            "VALUES (?,?,?,?,?,1,?,?,?,?)",
            (
                job_id,
                "a" * 64,
                "hermes",
                "QUEUED",
                "ACTIVE",
                now,
                now,
                record_json,
                record_sha256,
            ),
        )
        _append_prior_audit(
            conn,
            event_id="evt-1",
            job_id=job_id,
            kind="JOB_CREATED",
            payload={"phase": "QUEUED", "request_sha256": "a" * 64},
            created_at=now,
        )
        _append_prior_audit(
            conn,
            event_id="evt-2",
            job_id=job_id,
            kind="VALIDATION_RECEIPT_RECORDED",
            payload={"receipt_id": receipt_id, "receipt_sha256": receipt_sha256},
            created_at=now + 1,
        )
        conn.execute(
            "INSERT INTO review_challenges(challenge_id,job_id,kind,principal,nonce,"
            "issued_at,expires_at,status,challenge_json,challenge_sha256) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                challenge_id,
                job_id,
                "review",
                "codex_mcp",
                "n" * 32,
                "2026-08-13T00:00:00Z",
                "2026-08-13T01:00:00Z",
                "ACTIVE",
                challenge_json,
                challenge_sha256,
            ),
        )
        conn.execute(
            "INSERT INTO review_operations(op_id,job_id,kind,payload_sha256,"
            "result_json,revision,created_at) VALUES (?,?,?,?,?,?,?)",
            (
                "op-1",
                job_id,
                "PHASE_TRANSITION",
                "b" * 64,
                record_json,
                1,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO review_validation_receipts(receipt_id,job_id,snapshot_sha,"
            "receipt_json,receipt_sha256,created_at) VALUES (?,?,?,?,?,?)",
            (
                receipt_id,
                job_id,
                starting_sha,
                receipt_json,
                receipt_sha256,
                now,
            ),
        )
        conn.commit()
    return job_id


def test_populated_prior_schema_migrates_and_is_integrity_checked(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    db = tmp_path / "review.db"
    _populate_prior_store(db, worktree, starting_sha)

    with pytest.raises(AdapterError) as raised:
        ReviewStore(db)
    assert raised.value.code == "LEGACY_RECEIPT_KEY_REQUIRED"
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert "review_meta" not in tables


def test_prior_schema_corruption_fails_closed(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    db = tmp_path / "review.db"
    job_id = _populate_prior_store(db, worktree, starting_sha)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=? WHERE job_id=?",
            ('{"job_id": "corrupted"}', job_id),
        )
    with pytest.raises(AdapterError) as raised:
        ReviewStore(db)
    assert raised.value.code == "UNSUPPORTED_SCHEMA"


def test_prior_schema_incompatible_record_fails_closed_without_partial_stamp(tmp_path):
    worktree, starting_sha, _ = make_git_worktree(tmp_path)
    db = tmp_path / "review.db"
    job_id = _populate_prior_store(db, worktree, starting_sha)
    # Relabel the record to an unsupported schema version (hash recomputed).
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT record_json FROM review_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
    record = json.loads(row[0])
    record["schema_version"] = "9.9.9"
    new_json = json.dumps(record, sort_keys=True)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE review_jobs SET record_json=?, record_sha256=? WHERE job_id=?",
            (new_json, hashlib.sha256(new_json.encode()).hexdigest(), job_id),
        )
    with pytest.raises(AdapterError) as raised:
        ReviewStore(db)
    assert raised.value.code == "UNSUPPORTED_SCHEMA"
    # The failed migration must not partially stamp the new schema version.
    with sqlite3.connect(db) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert "review_meta" not in tables


def test_prior_schema_ambiguous_layout_fails_closed(tmp_path):
    db = tmp_path / "review.db"
    _create_prior_schema(db)
    with sqlite3.connect(db) as conn:
        conn.execute("ALTER TABLE review_jobs ADD COLUMN extra TEXT")
    with pytest.raises(AdapterError) as raised:
        ReviewStore(db)
    assert raised.value.code == "UNSUPPORTED_SCHEMA"


def test_durable_receipt_keys_survive_restart_and_reverify_history(tmp_path):
    worktree, starting_sha, remote = make_git_worktree(tmp_path)
    key_dir = tmp_path / "receipt-keys"
    authority = ReceiptAuthority.from_key_directory(key_dir)
    store = ReviewStore(tmp_path / "review.db", authority=authority)
    orch = ReviewOrchestrator(
        store,
        git=GitVerifier({REPOSITORY_ID: remote}),
        authority=authority,
        repository_roots=[tmp_path.resolve()],
    )
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    orch.record_review(
        "codex_mcp",
        payload["job_id"],
        {"receipt": build_review_receipt(authority, challenge)},
    )

    restarted = ReceiptAuthority.from_key_directory(key_dir)
    assert restarted.review_key_id == authority.review_key_id
    assert restarted.validation_key_id == authority.validation_key_id
    assert restarted.capsule_key_id == authority.capsule_key_id
    ReviewStore(tmp_path / "review.db", authority=restarted)
    for path in key_dir.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("fault", ["permission", "symlink", "corrupt"])
def test_durable_receipt_key_files_fail_closed(tmp_path, fault):
    key_dir = tmp_path / "receipt-keys"
    if fault == "symlink":
        key_dir.mkdir(mode=0o700)
        target = tmp_path / "target"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        (key_dir / "review-runner.key").symlink_to(target)
    else:
        ReceiptAuthority.from_key_directory(key_dir)
        key = key_dir / "review-runner.key"
        if fault == "permission":
            key.chmod(0o644)
        else:
            key.write_text("{}", encoding="utf-8")
            key.chmod(0o600)

    with pytest.raises(AdapterError) as raised:
        ReceiptAuthority.from_key_directory(key_dir)
    assert raised.value.code == "RECEIPT_KEY_INVALID"


def test_empty_1_2_store_migrates_receipt_metadata_transactionally(tmp_path):
    db = tmp_path / "review.db"
    ReviewStore(db)
    with sqlite3.connect(db) as conn:
        for table in ("review_runner_receipts", "review_validation_receipts"):
            conn.execute(f"ALTER TABLE {table} DROP COLUMN signing_key_id")
            conn.execute(f"ALTER TABLE {table} DROP COLUMN signing_algorithm")
            conn.execute(f"ALTER TABLE {table} DROP COLUMN proof")
        conn.execute("UPDATE review_meta SET value='1.2.0' WHERE key='schema_version'")

    ReviewStore(db)
    with sqlite3.connect(db) as conn:
        version = conn.execute(
            "SELECT value FROM review_meta WHERE key='schema_version'"
        ).fetchone()[0]
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(review_runner_receipts)")
        }
    assert version == SCHEMA_VERSION
    assert {"signing_key_id", "signing_algorithm", "proof"} <= columns


def test_legacy_receipt_migration_requires_key_and_rolls_back(tmp_path):
    orch, _, authority, worktree, starting_sha, _ = make_orchestrator(tmp_path)
    payload = create_payload(worktree, starting_sha)
    orch.create("hermes", payload)
    challenge = drive_to_reviewing(orch, payload["job_id"])
    orch.record_review(
        "codex_mcp",
        payload["job_id"],
        {"receipt": build_review_receipt(authority, challenge)},
    )
    db = tmp_path / "review.db"
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE review_meta SET value='1.2.0' WHERE key='schema_version'")

    with pytest.raises(AdapterError) as raised:
        ReviewStore(db, authority=authority)
    assert raised.value.code == "AUDIT_ROLLBACK"
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute(
                "SELECT value FROM review_meta WHERE key='schema_version'"
            ).fetchone()[0]
            == "1.2.0"
        )
