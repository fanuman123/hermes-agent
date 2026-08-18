"""Trusted runner/validator receipt authority for the review orchestrator.

This module is the narrow trust boundary that closes the two BLOCKER findings:

* A **review runner receipt** is minted by the adapter's read-only Codex
  execution boundary *after* it has independently observed the before/after
  worktree snapshot through :class:`~.gitops.GitVerifier`.  It is authenticated
  with a runner-only HMAC secret that ordinary API principals never receive.
* A **validation runner receipt** is minted by the validator-only capability
  *after* the isolated validation path has executed.  It is authenticated with
  a distinct validator-only HMAC secret.

The secrets live only in :class:`ReceiptAuthority`, which is held by the
runtime's internal runner/validator boundaries.  The public HTTP surface can
request a challenge and submit an opaque, already-minted receipt; it can never
mint the trusted fields because it never sees the secrets.

Both receipt shapes are strict (allowlisted) pydantic models: no arbitrary
invocation dictionaries, bounded sizes, and credential-pattern redaction in
values as defense in depth.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, field_validator

from .canonical import canonical_json_bytes, sha256_bytes
from .errors import AdapterError
from .models import StrictModel

RECEIPT_SCHEMA_VERSION = "1.0.0"

_RECEIPT_KIND_REVIEW = "review_runner"
_RECEIPT_KIND_VALIDATION = "validation_runner"

_SHA_RE = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
_HEX64_RE = r"^[0-9a-f]{64}$"

# ── Value-level credential redaction (defense in depth) ─────────────────────
# Key-name redaction alone misses ``{"command": "tool --token actual-secret"}``.
# These patterns scrub credential-shaped material from string *values* too.
_CREDENTIAL_VALUE_PATTERNS = (
    # Authorization header — may carry a "Bearer <token>" pair; scrub it all.
    re.compile(
        r"(?i)(\bauthorization\b\s*[:=]\s*)(bearer\s+[^\s,;\"']+|[^\s,;\"']+)"
    ),
    # key=value / key: value credential tokens.
    re.compile(
        r"(?i)(\b(?:token|secret|password|passwd|api[_-]?key|credential|auth)\b"
        r"\s*[:=]\s*)([^\s,;\"']+)"
    ),
    # bare Bearer token.
    re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]+)"),
    # CLI flag tokens.
    re.compile(r"(?i)(--(?:token|secret|password|api-key|apikey|api_key)\s+)([^\s]+)"),
)

_CREDENTIAL_KEY_MARKERS = (
    "secret",
    "token",
    "password",
    "credential",
    "api_key",
    "api-key",
    "authorization",
)


def redact_secrets(value):
    """Scrub credential-shaped substrings inside string values, in place-ish.

    Idempotent: ``[REDACTED]`` never matches the patterns, so re-running is a
    no-op.  Used before receipts are signed so secrets never enter the signed
    body, and again at audit-persistence time as defense in depth.
    """
    if isinstance(value, str):
        for pattern in _CREDENTIAL_VALUE_PATTERNS:
            value = pattern.sub(lambda match: match.group(1) + "[REDACTED]", value)
        return value
    if isinstance(value, dict):
        return {key: redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def redact(value):
    """Key-name redaction plus value-level credential redaction."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _CREDENTIAL_KEY_MARKERS):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value


def _validate_uuid(value: str) -> str:
    from uuid import UUID

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


# ── Receipt models ──────────────────────────────────────────────────────────
class ReceiptFinding(StrictModel):
    """A single review finding carried inside a signed runner receipt."""

    severity: Literal["BLOCKER", "MAJOR", "MINOR"]
    title: str = Field(min_length=1, max_length=200)
    path: str = ""
    detail: str = ""


class RunnerInvocation(StrictModel):
    """Allowlisted invocation evidence for a read-only review run.

    The free-form invocation dict is replaced by this fixed, bounded schema;
    any key outside the allowlist is rejected by ``extra="forbid"``.
    """

    runner: str = Field(min_length=1, max_length=100)
    runner_version: str = Field(min_length=1, max_length=50)
    sandbox: Literal["read_only", "isolated"] = "read_only"
    approval_policy: Literal["never", "manual"] = "never"
    command: str = Field(min_length=1, max_length=1000)
    model: str | None = Field(default=None, max_length=200)
    provider: str | None = Field(default=None, max_length=100)


class CodexRunResult(StrictModel):
    """Bounded, server-owned result of a concrete read-only Codex run.

    The concrete backend returns only these fields.  ``thread_id`` and the
    ``findings`` are captured from the subprocess's structured output, but the
    ``response_sha256`` is recomputed by the backend from the raw response
    bytes it captured and ``zero_write`` is the backend's own attestation that
    the read-only sandbox observed no write.  There is no field here for
    ``modified_files``, invocation identity, sandbox, approval policy, or a
    caller-authored response hash -- those are owned by :class:`ReviewRunner`
    and cannot be injected through this boundary.
    """

    thread_id: str = Field(min_length=1, max_length=200)
    response_sha256: str = Field(pattern=_HEX64_RE)
    zero_write: bool
    findings: list[ReceiptFinding] = Field(default_factory=list)


class _CodexBoundaryOutput(StrictModel):
    """Strict shape for the read-only Codex subprocess's stdout.

    ``extra="forbid"`` rejects any attempt by the boundary to smuggle
    ``modified_files``, ``sandbox``, ``identity``, ``invocation``, ``version``,
    ``approval_policy``, or a precomputed response hash into the result.
    """

    thread_id: str = Field(min_length=1, max_length=200)
    response: str = Field(min_length=1)
    zero_write: bool
    findings: list[ReceiptFinding] = Field(default_factory=list)



class ReviewRunnerReceipt(StrictModel):
    """Signed, snapshot-bound review receipt issued by the Codex execution
    boundary.  ``proof`` authenticates every other field via HMAC."""

    schema_version: Literal["1.0.0"] = RECEIPT_SCHEMA_VERSION
    receipt_kind: Literal["review_runner"] = _RECEIPT_KIND_REVIEW
    receipt_id: str = Field(min_length=16, max_length=128)
    challenge_id: str = Field(min_length=32, max_length=128)
    challenge_nonce: str = Field(min_length=32, max_length=128)
    job_id: str
    kind: Literal["review"] = "review"
    principal: Literal["codex_mcp"] = "codex_mcp"
    review_round: int = Field(ge=1)
    prompt_sha256: str = Field(pattern=_HEX64_RE)
    response_sha256: str = Field(pattern=_HEX64_RE)
    codex_thread_id: str = Field(min_length=1, max_length=200)
    codex_cli_version: str = Field(min_length=1, max_length=50)
    modified_files: int = Field(ge=0)
    invocation: RunnerInvocation
    before_head: str = Field(pattern=_SHA_RE)
    after_head: str = Field(pattern=_SHA_RE)
    before_diff_hash: str = Field(pattern=_HEX64_RE)
    after_diff_hash: str = Field(pattern=_HEX64_RE)
    allowed_paths: list[str] = Field(min_length=1)
    findings: list[ReceiptFinding] = Field(default_factory=list)
    started_at: str = Field(min_length=1)
    finished_at: str = Field(min_length=1)
    proof: str = Field(pattern=_HEX64_RE)

    @field_validator("job_id")
    @classmethod
    def _job_id(cls, value: str) -> str:
        return _validate_uuid(value)

    @field_validator("allowed_paths")
    @classmethod
    def _allowed(cls, value: list[str]) -> list[str]:
        return [_validate_relative_path(item) for item in value]


class CheckReceipt(StrictModel):
    """One isolated-validation check, with its identity and evidence digest."""

    command_id: str = Field(min_length=1, max_length=200)
    check_group: str = Field(min_length=1, max_length=100)
    exit_status: int
    required: bool = True
    evidence_sha256: str | None = Field(default=None, pattern=_HEX64_RE)


class ValidationRunnerReceipt(StrictModel):
    """Signed, snapshot-bound validation receipt issued by the validator-only
    capability after the isolated validation path has run to completion."""

    schema_version: Literal["1.0.0"] = RECEIPT_SCHEMA_VERSION
    receipt_kind: Literal["validation_runner"] = _RECEIPT_KIND_VALIDATION
    receipt_id: str = Field(min_length=16, max_length=128)
    challenge_id: str = Field(min_length=32, max_length=128)
    challenge_nonce: str = Field(min_length=32, max_length=128)
    job_id: str
    kind: Literal["verification"] = "verification"
    principal: Literal["hermes"] = "hermes"
    review_round: int = Field(ge=0)
    snapshot_sha: str = Field(pattern=_SHA_RE)
    current_head: str = Field(pattern=_SHA_RE)
    current_diff_hash: str = Field(pattern=_HEX64_RE)
    allowed_paths: list[str] = Field(min_length=1)
    validator_id: str = Field(min_length=1, max_length=100)
    validator_version: str = Field(min_length=1, max_length=50)
    profile_id: str = Field(min_length=1, max_length=100)
    check_groups: list[CheckReceipt] = Field(min_length=1)
    pass_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    boundary_result: Literal["PASSED", "FAILED"]
    evidence_sha256: str = Field(pattern=_HEX64_RE)
    started_at: str = Field(min_length=1)
    finished_at: str = Field(min_length=1)
    proof: str = Field(pattern=_HEX64_RE)

    @field_validator("job_id")
    @classmethod
    def _job_id(cls, value: str) -> str:
        return _validate_uuid(value)

    @field_validator("allowed_paths")
    @classmethod
    def _allowed(cls, value: list[str]) -> list[str]:
        return [_validate_relative_path(item) for item in value]


def validation_evidence_material(
    *,
    check_groups: list[dict],
    pass_count: int,
    fail_count: int,
    boundary_result: str,
    snapshot_sha: str,
    current_diff_hash: str,
) -> bytes:
    """Canonical material over which ``evidence_sha256`` is computed.

    Both the validator (at mint time) and the orchestrator (at verification
    time) recompute this exact digest; any drift fails closed.
    """
    return canonical_json_bytes(
        {
            "check_groups": check_groups,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "boundary_result": boundary_result,
            "snapshot_sha": snapshot_sha,
            "current_diff_hash": current_diff_hash,
        }
    )


# ── Receipt authority ───────────────────────────────────────────────────────
class ReceiptAuthority:
    """Holds the runner-only and validator-only HMAC secrets.

    Constructed once by the runtime and shared with the internal runner and
    validator boundaries (which mint) and the orchestrator (which verifies).
    The secrets are never exposed through the HTTP service surface.
    """

    def __init__(
        self,
        *,
        review_runner_secret: bytes | None = None,
        validation_runner_secret: bytes | None = None,
    ):
        self._review_secret = review_runner_secret or secrets.token_bytes(32)
        self._validation_secret = validation_runner_secret or secrets.token_bytes(32)

    @staticmethod
    def _sign(secret: bytes, body: dict) -> str:
        return hmac.new(secret, canonical_json_bytes(body), hashlib.sha256).hexdigest()

    @staticmethod
    def _body(receipt: dict) -> dict:
        return {key: value for key, value in receipt.items() if key != "proof"}

    # -- review runner receipts ------------------------------------------------
    def mint_review(self, fields: dict) -> dict:
        """Sign a review runner receipt.  Credential-shaped material in the
        allowlisted invocation is redacted before it enters the signed body."""
        body = dict(fields)
        body.pop("proof", None)
        if isinstance(body.get("invocation"), dict):
            body["invocation"] = redact_secrets(body["invocation"])
        # Validate the body first so bad fields never reach the signature.
        ReviewRunnerReceipt.model_validate({**body, "proof": "0" * 64})
        proof = self._sign(self._review_secret, body)
        receipt = {**body, "proof": proof}
        ReviewRunnerReceipt.model_validate(receipt)
        return receipt

    def verify_review(self, receipt: dict) -> ReviewRunnerReceipt:
        model = ReviewRunnerReceipt.model_validate(receipt)
        expected = self._sign(self._review_secret, self._body(receipt))
        if not hmac.compare_digest(expected, receipt["proof"]):
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED", "review runner receipt proof is invalid"
            )
        return model

    # -- validation runner receipts -------------------------------------------
    def mint_validation(self, fields: dict) -> dict:
        body = dict(fields)
        body.pop("proof", None)
        ValidationRunnerReceipt.model_validate({**body, "proof": "0" * 64})
        proof = self._sign(self._validation_secret, body)
        receipt = {**body, "proof": proof}
        ValidationRunnerReceipt.model_validate(receipt)
        return receipt

    def verify_validation(self, receipt: dict) -> ValidationRunnerReceipt:
        model = ValidationRunnerReceipt.model_validate(receipt)
        expected = self._sign(self._validation_secret, self._body(receipt))
        if not hmac.compare_digest(expected, receipt["proof"]):
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED",
                "validation runner receipt proof is invalid",
            )
        return model


def new_receipt_id() -> str:
    return "rcpt-" + secrets.token_hex(24)


def compute_validation_evidence_sha256(
    *,
    check_groups: list[dict],
    pass_count: int,
    fail_count: int,
    boundary_result: str,
    snapshot_sha: str,
    current_diff_hash: str,
) -> str:
    return sha256_bytes(
        validation_evidence_material(
            check_groups=check_groups,
            pass_count=pass_count,
            fail_count=fail_count,
            boundary_result=boundary_result,
            snapshot_sha=snapshot_sha,
            current_diff_hash=current_diff_hash,
        )
    )


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Trusted runner / validator boundaries ───────────────────────────────────
class CodexReviewBackend:
    """Concrete, adapter-owned read-only Codex execution boundary.

    The runner owns this configuration: the executable, version, and identity
    are fixed at construction (from runtime settings) and are never accepted
    from a callback or subprocess output.  ``run`` launches the configured
    runner boundary in a read-only sandbox with approval disabled, binds the
    active challenge and prompt, and returns only the server-derived evidence
    the runner signs: thread id, a recomputed response hash, the boundary's
    zero-write attestation, and the findings it reported.

    Zero-write is proven two ways and fails closed if either is unavailable:

    * a metadata snapshot (inode/size/mtime/ctime) of the monitored paths is
      taken before and after the run -- any change proves a write, even a
      write-and-restore that the two Git snapshots could not distinguish; and
    * the subprocess must itself attest ``zero_write`` in its strict output.

    The subprocess's stdout is validated against a strict model with
    ``extra="forbid"``, so a malicious boundary cannot inject ``modified_files``,
    ``sandbox``, ``identity``, ``invocation``, ``version``, or a precomputed
    response hash -- those fields are structurally impossible to smuggle.
    """

    def __init__(
        self,
        *,
        executable: str,
        version: str,
        identity: str,
        timeout_seconds: int = 1800,
    ):
        if not executable:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner executable is not configured"
            )
        try:
            resolved = Path(executable).resolve(strict=True)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner executable is unavailable"
            ) from exc
        if not resolved.is_file():
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "read-only Codex runner executable is not a regular file",
            )
        if not version:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner version is not configured"
            )
        if not identity:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner identity is not configured"
            )
        self.executable = str(resolved)
        self.version = version
        self.identity = identity
        self.timeout_seconds = timeout_seconds

    def _argv(self) -> list[str]:
        return [
            self.executable,
            "review",
            "--sandbox=read-only",
            "--approval-policy=never",
            "--format=json",
        ]

    def invocation(self) -> dict:
        return {
            "runner": self.identity,
            "runner_version": self.version,
            "sandbox": "read_only",
            "approval_policy": "never",
            "command": " ".join(self._argv()),
        }

    @staticmethod
    def _environment(challenge_id: str) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "HERMES_REVIEW_CHALLENGE_ID": challenge_id,
        }

    @staticmethod
    def _stat_snapshot(root: Path, paths: list[str]) -> dict[str, tuple | None]:
        snapshot: dict[str, tuple | None] = {}
        for relpath in paths:
            candidate = root / relpath
            try:
                info = candidate.lstat()
            except OSError:
                snapshot[relpath] = None
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                snapshot[relpath] = None
                continue
            snapshot[relpath] = (
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        return snapshot

    def run(
        self,
        *,
        prompt: str,
        cwd: Path,
        challenge_id: str,
        monitor_paths: list[str] | None = None,
    ) -> CodexRunResult:
        root = Path(cwd)
        monitor = list(monitor_paths or [])
        before = self._stat_snapshot(root, monitor)
        try:
            proc = subprocess.run(
                self._argv(),
                input=prompt.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
                cwd=str(root),
                env=self._environment(challenge_id),
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex review timed out"
            ) from exc
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex review could not be launched"
            ) from exc
        after = self._stat_snapshot(root, monitor)
        if before != after:
            raise AdapterError(
                "ZERO_WRITE_UNPROVEN",
                "read-only Codex review modified worktree files",
            )
        if proc.returncode != 0:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex review exited non-zero"
            )
        try:
            raw = json.loads(proc.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "read-only Codex review produced no structured result",
            ) from exc
        try:
            boundary = _CodexBoundaryOutput.model_validate(raw)
        except ValidationError as exc:
            raise AdapterError(
                "ZERO_WRITE_UNPROVEN",
                "read-only Codex review result is not trustworthy",
            ) from exc
        if not boundary.zero_write:
            raise AdapterError(
                "ZERO_WRITE_UNPROVEN",
                "read-only Codex boundary did not attest a zero-write run",
            )
        return CodexRunResult(
            thread_id=boundary.thread_id,
            response_sha256=sha256_bytes(boundary.response.encode("utf-8")),
            zero_write=True,
            findings=boundary.findings,
        )


class ReviewRunner:
    """Adapter-owned read-only Codex execution boundary.

    Observes the worktree snapshot through the repository boundary before and
    after the review, executes the concrete read-only Codex backend, computes
    the modified-file proof itself from the server observations, and mints the
    signed review runner receipt.  Invocation identity, sandbox, approval
    policy, and the response hash are owned here -- never accepted from the
    backend as arbitrary callback fields.
    """

    def __init__(self, git, authority: ReceiptAuthority, backend: CodexReviewBackend):
        self.git = git
        self.authority = authority
        self.backend = backend

    def _observe(self, challenge: dict) -> dict:
        return self.git.observe_review_snapshot(
            challenge["worktree_path"],
            repository_id=challenge["repository_id"],
            branch=challenge["branch"],
            starting_sha=challenge["starting_sha"],
            allowed_paths=challenge["allowed_paths"],
        )

    @staticmethod
    def _modified_count(before: dict, after: dict) -> int:
        before_hashes = before.get("path_hashes", {})
        after_hashes = after.get("path_hashes", {})
        keys = set(before_hashes) | set(after_hashes)
        return sum(1 for key in keys if before_hashes.get(key) != after_hashes.get(key))

    def run(self, *, challenge: dict, prompt: str) -> dict:
        if sha256_bytes(prompt.encode("utf-8")) != challenge["prompt_sha256"]:
            raise AdapterError(
                "CHALLENGE_MISMATCH",
                "review prompt does not match the issued challenge",
            )
        before = self._observe(challenge)
        started_at = _utc_now()
        result = self.backend.run(
            prompt=prompt,
            cwd=Path(challenge["worktree_path"]),
            challenge_id=challenge["challenge_id"],
            monitor_paths=before.get("changed_paths", []),
        )
        finished_at = _utc_now()
        after = self._observe(challenge)
        modified_files = self._modified_count(before, after)
        snapshot_consistent = (
            before["head"] == after["head"]
            and before["diff_hash"] == after["diff_hash"]
        )
        if modified_files == 0 and not snapshot_consistent:
            modified_files = 1
        if modified_files == 0 and not result.zero_write:
            # Snapshots cannot rule out a write-and-restore; the backend's
            # read-only sandbox proof is required and unavailable.
            raise AdapterError(
                "ZERO_WRITE_UNPROVEN",
                "review runner could not prove a zero-write run",
            )
        fields = {
            "receipt_id": new_receipt_id(),
            "challenge_id": challenge["challenge_id"],
            "challenge_nonce": challenge["nonce"],
            "job_id": challenge["job_id"],
            "kind": challenge["kind"],
            "principal": challenge["principal"],
            "review_round": challenge["review_round"],
            "prompt_sha256": challenge["prompt_sha256"],
            "response_sha256": result.response_sha256,
            "codex_thread_id": result.thread_id,
            "codex_cli_version": self.backend.version,
            "modified_files": modified_files,
            "invocation": self.backend.invocation(),
            "before_head": before["head"],
            "after_head": after["head"],
            "before_diff_hash": before["diff_hash"],
            "after_diff_hash": after["diff_hash"],
            "allowed_paths": list(challenge["allowed_paths"]),
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
            "started_at": started_at,
            "finished_at": finished_at,
        }
        return self.authority.mint_review(fields)


class ValidationAttestor:
    """Validator-only capability.

    Observes the worktree snapshot, executes the isolated validation path
    through the registered :class:`~.validation.ValidationRunner`, and mints
    the signed validation receipt.  ``profiles`` supplies the check-group
    metadata (``required``, ``check_group``) that the runner result omits.
    """

    def __init__(self, git, authority: ReceiptAuthority, validation, profiles: dict):
        self.git = git
        self.authority = authority
        self.validation = validation
        self.profiles = profiles

    @staticmethod
    def _validate_completed_result(result) -> dict:
        """Require a real, completed isolated-validation result.

        A caller-authored or partial result (missing ``overall_status``, an
        empty check list, or a check missing its identity/exit status) is
        rejected fail-closed rather than being signed into a receipt.
        """
        if not isinstance(result, dict):
            raise AdapterError(
                "VALIDATION_CONTAINMENT_UNAVAILABLE",
                "isolated validation produced no result",
            )
        if result.get("overall_status") not in {"PASSED", "FAILED"}:
            raise AdapterError(
                "VALIDATION_CONTAINMENT_UNAVAILABLE",
                "isolated validation result is incomplete",
            )
        commands = result.get("commands")
        if not isinstance(commands, list) or not commands:
            raise AdapterError(
                "VALIDATION_CONTAINMENT_UNAVAILABLE",
                "isolated validation produced no check results",
            )
        for command in commands:
            if not isinstance(command, dict):
                raise AdapterError(
                    "VALIDATION_CONTAINMENT_UNAVAILABLE",
                    "isolated validation check result is malformed",
                )
            if "command_id" not in command or "exit_status" not in command:
                raise AdapterError(
                    "VALIDATION_CONTAINMENT_UNAVAILABLE",
                    "isolated validation check result is incomplete",
                )
        return result

    def run(self, *, challenge: dict, profile_id: str) -> dict:
        snapshot = self.git.observe_review_snapshot(
            challenge["worktree_path"],
            repository_id=challenge["repository_id"],
            branch=challenge["branch"],
            starting_sha=challenge["starting_sha"],
            allowed_paths=challenge["allowed_paths"],
        )
        result = self._validate_completed_result(
            self.validation.run(
                profile_id, Path(challenge["worktree_path"]), snapshot["head"]
            )
        )
        profile = self.profiles.get(profile_id, {})
        required_by_id = {
            command["command_id"]: bool(command.get("required", True))
            for command in profile.get("commands", [])
        }
        check_groups = []
        started_at = None
        finished_at = None
        for command in result.get("commands", []):
            started_at = started_at or command.get("started_at")
            finished_at = command.get("finished_at") or finished_at
            check_groups.append(
                {
                    "command_id": command["command_id"],
                    "check_group": profile.get("check_group", "validation"),
                    "exit_status": command["exit_status"],
                    "required": required_by_id.get(command["command_id"], True),
                    "evidence_sha256": command.get("stdout_sha256"),
                }
            )
        pass_count = sum(1 for group in check_groups if group["exit_status"] == 0)
        fail_count = sum(1 for group in check_groups if group["exit_status"] != 0)
        boundary = "PASSED" if result.get("overall_status") == "PASSED" else "FAILED"
        fields = {
            "receipt_id": new_receipt_id(),
            "challenge_id": challenge["challenge_id"],
            "challenge_nonce": challenge["nonce"],
            "job_id": challenge["job_id"],
            "kind": challenge["kind"],
            "principal": challenge["principal"],
            "review_round": challenge["review_round"],
            "snapshot_sha": snapshot["head"],
            "current_head": snapshot["head"],
            "current_diff_hash": snapshot["diff_hash"],
            "allowed_paths": list(challenge["allowed_paths"]),
            "validator_id": "hermes.builder_review.validation",
            "validator_version": "1.0.0",
            "profile_id": profile_id,
            "check_groups": check_groups,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "boundary_result": boundary,
            "evidence_sha256": compute_validation_evidence_sha256(
                check_groups=check_groups,
                pass_count=pass_count,
                fail_count=fail_count,
                boundary_result=boundary,
                snapshot_sha=snapshot["head"],
                current_diff_hash=snapshot["diff_hash"],
            ),
            "started_at": started_at or _utc_now(),
            "finished_at": finished_at or _utc_now(),
        }
        return self.authority.mint_validation(fields)
