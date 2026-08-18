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
import selectors
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, field_validator

from .canonical import canonical_json_bytes, sha256_bytes
from .errors import AdapterError
from .models import StrictModel

RECEIPT_SCHEMA_VERSION = "1.0.0"
SIGNING_ALGORITHM = "hmac-sha256-v1"

_RECEIPT_KIND_REVIEW = "review_runner"
_RECEIPT_KIND_VALIDATION = "validation_runner"

_SHA_RE = r"^[0-9a-f]{40}([0-9a-f]{24})?$"
_HEX64_RE = r"^[0-9a-f]{64}$"

_MAX_BOUNDARY_STDOUT_BYTES = 256 * 1024
_MAX_BOUNDARY_STDERR_BYTES = 64 * 1024
_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_SANDBOX_LAUNCHER_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_CHARS = 64 * 1024
_MAX_FINDINGS = 50
_MAX_FINDINGS_BYTES = 128 * 1024
_MAX_FINDING_PATH_CHARS = 500
_MAX_FINDING_DETAIL_CHARS = 4000

_SANDBOX_SCOPE = (
    "protects_original_worktree_git_metadata_config_state_keys_network_and_writes;"
    "not_whole_host_read_isolation"
)

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
    # Cookie and proxy-authentication headers.
    re.compile(
        r"(?i)(\b(?:cookie|set-cookie|proxy-authorization|x-api-key)\b\s*[:=]\s*)"
        r"([^\r\n]+)"
    ),
    # Common environment-variable spellings, including provider-prefixed names.
    re.compile(
        r"(?i)(\b(?:AWS_SECRET_ACCESS_KEY|[A-Z][A-Z0-9_]*_(?:SECRET|TOKEN|PASSWORD))"
        r"\b\s*[:=]\s*)([^\s,;\"']+)"
    ),
    # Credentials embedded in URLs.
    re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@"),
    # PEM/OpenSSH private-key bodies.
    re.compile(
        r"(?is)(-----BEGIN [^-\r\n]*PRIVATE KEY-----).*?"
        r"(-----END [^-\r\n]*PRIVATE KEY-----)"
    ),
    # Well-known provider token prefixes.  Keep the prefix for diagnostics.
    re.compile(
        r"(?i)\b(gh[pousr]_|github_pat_|sk-(?:proj-)?|xox[baprs]-|AKIA|ASIA)"
        r"[A-Za-z0-9._~+/=-]{8,}"
    ),
)

_CREDENTIAL_KEY_MARKERS = (
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "api_key",
    "api-key",
    "access_key",
    "private_key",
    "cookie",
    "auth",
    "authorization",
)


def _posix_effective_uid() -> int:
    """Return the POSIX effective UID or fail closed on unsupported hosts."""
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise AdapterError(
            "CODEX_UNAVAILABLE",
            "POSIX effective-user identity checks are unavailable",
        )
    uid = getter()
    if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0:
        raise AdapterError(
            "CODEX_UNAVAILABLE", "POSIX effective-user identity is invalid"
        )
    return uid


def redact_secrets(value):
    """Scrub credential-shaped substrings inside string values, in place-ish.

    Idempotent: ``[REDACTED]`` never matches the patterns, so re-running is a
    no-op.  Used before receipts are signed so secrets never enter the signed
    body, and again at audit-persistence time as defense in depth.
    """
    if isinstance(value, str):
        for pattern in _CREDENTIAL_VALUE_PATTERNS:
            def replacement(match):
                if pattern.pattern.startswith("(?i)(\\b[a-z"):
                    return match.group(1) + "[REDACTED]@"
                if "PRIVATE KEY" in pattern.pattern:
                    return match.group(1) + "\n[REDACTED]\n" + match.group(2)
                return match.group(1) + "[REDACTED]"

            value = pattern.sub(replacement, value)
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
    path: str = Field(default="", max_length=_MAX_FINDING_PATH_CHARS)
    detail: str = Field(default="", max_length=_MAX_FINDING_DETAIL_CHARS)

    @field_validator("title", "detail", mode="before")
    @classmethod
    def _redact_text(cls, value):
        if isinstance(value, str):
            return redact_secrets(value)
        return value

    @field_validator("path", mode="before")
    @classmethod
    def _redact_path(cls, value):
        if isinstance(value, str):
            return redact_secrets(value)
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value:
            return value
        return _validate_relative_path(value)


class RunnerInvocation(StrictModel):
    """Allowlisted invocation evidence for a read-only review run.

    The free-form invocation dict is replaced by this fixed, bounded schema;
    any key outside the allowlist is rejected by ``extra="forbid"``.
    """

    runner: str = Field(min_length=1, max_length=100)
    runner_version: str = Field(min_length=1, max_length=50)
    sandbox: Literal["read_only", "isolated"] = "read_only"
    sandbox_scope: Literal[
        "protects_original_worktree_git_metadata_config_state_keys_network_and_writes;"
        "not_whole_host_read_isolation"
    ] = _SANDBOX_SCOPE
    approval_policy: Literal["never", "manual"] = "never"
    command: str = Field(min_length=1, max_length=1000)
    model: str | None = Field(default=None, max_length=200)
    provider: str | None = Field(default=None, max_length=100)


class CodexRunResult(StrictModel):
    """Bounded, server-owned result of a concrete read-only Codex run.

    The concrete backend returns only these fields.  ``thread_id`` and the
    ``findings`` are captured from the subprocess's structured output, but the
    ``response_sha256`` is recomputed by the backend from the redacted,
    bounded response it captured.  Zero-write evidence is established by the
    trusted parent and deliberately is not accepted in this model.  There is no field here for
    ``modified_files``, invocation identity, sandbox, approval policy, or a
    caller-authored response hash -- those are owned by :class:`ReviewRunner`
    and cannot be injected through this boundary.
    """

    thread_id: str = Field(min_length=1, max_length=200)
    response_sha256: str = Field(pattern=_HEX64_RE)
    findings: list[ReceiptFinding] = Field(default_factory=list, max_length=_MAX_FINDINGS)

    @field_validator("thread_id", mode="before")
    @classmethod
    def _redact_thread_id(cls, value):
        return redact_secrets(value) if isinstance(value, str) else value


class _CodexBoundaryOutput(StrictModel):
    """Strict shape for the read-only Codex subprocess's stdout.

    ``extra="forbid"`` rejects any attempt by the boundary to smuggle
    ``modified_files``, ``sandbox``, ``identity``, ``invocation``, ``version``,
    ``approval_policy``, or a precomputed response hash into the result.
    """

    thread_id: str = Field(min_length=1, max_length=200)
    response: str = Field(min_length=1, max_length=_MAX_RESPONSE_CHARS)
    findings: list[ReceiptFinding] = Field(default_factory=list, max_length=_MAX_FINDINGS)

    @field_validator("thread_id", mode="before")
    @classmethod
    def _redact_thread_id(cls, value):
        return redact_secrets(value) if isinstance(value, str) else value

    @field_validator("response", mode="before")
    @classmethod
    def _redact_response(cls, value):
        if isinstance(value, str):
            return redact_secrets(value)
        return value



class ReviewRunnerReceipt(StrictModel):
    """Signed, snapshot-bound review receipt issued by the Codex execution
    boundary.  ``proof`` authenticates every other field via HMAC."""

    schema_version: Literal["1.0.0"] = RECEIPT_SCHEMA_VERSION
    receipt_kind: Literal["review_runner"] = _RECEIPT_KIND_REVIEW
    signing_key_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    signing_algorithm: Literal["hmac-sha256-v1"] = SIGNING_ALGORITHM
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
    findings: list[ReceiptFinding] = Field(default_factory=list, max_length=_MAX_FINDINGS)
    started_at: str = Field(min_length=1)
    finished_at: str = Field(min_length=1)
    proof: str = Field(pattern=_HEX64_RE)

    @field_validator("codex_thread_id", mode="before")
    @classmethod
    def _redact_thread_id(cls, value):
        return redact_secrets(value) if isinstance(value, str) else value

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
    signing_key_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    signing_algorithm: Literal["hmac-sha256-v1"] = SIGNING_ALGORITHM
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
        capsule_checkpoint_secret: bytes | None = None,
    ):
        self._review_secret = review_runner_secret or secrets.token_bytes(32)
        self._validation_secret = validation_runner_secret or secrets.token_bytes(32)
        self._capsule_secret = capsule_checkpoint_secret or secrets.token_bytes(32)
        self.review_key_id = self._key_id("review-runner", self._review_secret)
        self.validation_key_id = self._key_id(
            "validation-runner", self._validation_secret
        )
        self.capsule_key_id = self._key_id("capsule-checkpoint", self._capsule_secret)

    @staticmethod
    def _key_id(purpose: str, secret: bytes) -> str:
        return hashlib.sha256(purpose.encode("ascii") + b"\0" + secret).hexdigest()[:32]

    @staticmethod
    def _read_or_create_key(directory: Path, filename: str, purpose: str) -> bytes:
        """Load or exclusively create one owner-only durable signing key.

        Existing unsafe/corrupt files always fail closed.  They are never
        replaced or regenerated.  Creation is O_EXCL, non-following, fsynced,
        and the containing owner-only directory is fsynced before return.
        """
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            directory_info = directory.lstat()
        except OSError as exc:
            raise AdapterError(
                "RECEIPT_KEY_INVALID", "receipt key directory is inaccessible"
            ) from exc
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()  # windows-footgun: ok
            or stat.S_IMODE(directory_info.st_mode) & 0o077
        ):
            raise AdapterError(
                "RECEIPT_KEY_INVALID", "owner-only receipt key directory required"
            )

        path = directory / filename
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        created = False
        try:
            descriptor = os.open(path, flags, 0o600)
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                raise AdapterError(
                    "RECEIPT_KEY_INVALID", "receipt signing key could not be opened safely"
                ) from exc
        except OSError as exc:
            raise AdapterError(
                "RECEIPT_KEY_INVALID", "receipt signing key could not be created safely"
            ) from exc

        try:
            if created:
                secret = secrets.token_bytes(32)
                payload = canonical_json_bytes(
                    {
                        "schema_version": "1.0.0",
                        "purpose": purpose,
                        "secret_hex": secret.hex(),
                        "checksum_sha256": hashlib.sha256(
                            purpose.encode("ascii") + b"\0" + secret
                        ).hexdigest(),
                    }
                )
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, payload[written:])
                os.fsync(descriptor)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()  # windows-footgun: ok
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= 1024
            ):
                raise AdapterError(
                    "RECEIPT_KEY_INVALID", "owner-only receipt signing key required"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = b""
            while len(raw) < 1025:
                chunk = os.read(descriptor, 1025 - len(raw))
                if not chunk:
                    break
                raw += chunk
            try:
                record = json.loads(raw)
                if not isinstance(record, dict) or set(record) != {
                    "schema_version",
                    "purpose",
                    "secret_hex",
                    "checksum_sha256",
                }:
                    raise ValueError("unexpected key fields")
                secret = bytes.fromhex(record["secret_hex"])
            except (UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
                raise AdapterError(
                    "RECEIPT_KEY_INVALID", "receipt signing key is corrupt"
                ) from exc
            expected_checksum = hashlib.sha256(
                purpose.encode("ascii") + b"\0" + secret
            ).hexdigest()
            if (
                record["schema_version"] != "1.0.0"
                or record["purpose"] != purpose
                or len(secret) != 32
                or not isinstance(record["checksum_sha256"], str)
                or not hmac.compare_digest(record["checksum_sha256"], expected_checksum)
            ):
                raise AdapterError(
                    "RECEIPT_KEY_INVALID", "receipt signing key is corrupt"
                )
        finally:
            os.close(descriptor)

        if created:
            directory_descriptor = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        return secret

    @classmethod
    def from_key_directory(cls, directory: str | Path) -> "ReceiptAuthority":
        """Build a restart-stable, purpose-separated authority."""
        root = Path(directory)
        return cls(
            review_runner_secret=cls._read_or_create_key(
                root, "review-runner.key", "review-runner"
            ),
            validation_runner_secret=cls._read_or_create_key(
                root, "validation-runner.key", "validation-runner"
            ),
            capsule_checkpoint_secret=cls._read_or_create_key(
                root, "capsule-checkpoint.key", "capsule-checkpoint"
            ),
        )

    @staticmethod
    def _sign(secret: bytes, body: dict) -> str:
        return hmac.new(secret, canonical_json_bytes(body), hashlib.sha256).hexdigest()

    @staticmethod
    def _body(receipt: dict) -> dict:
        return {key: value for key, value in receipt.items() if key != "proof"}

    # -- review runner receipts ------------------------------------------------
    def mint_review(self, fields: dict) -> dict:
        """Sign a review runner receipt.  Credential-shaped material in the
        allowlisted invocation and findings is redacted before it enters the
        signed body."""
        body = dict(fields)
        body.pop("proof", None)
        body["signing_key_id"] = self.review_key_id
        body["signing_algorithm"] = SIGNING_ALGORITHM
        if isinstance(body.get("invocation"), dict):
            body["invocation"] = redact_secrets(body["invocation"])
        if isinstance(body.get("findings"), list):
            body["findings"] = [
                ReceiptFinding.model_validate(finding).model_dump(mode="json")
                for finding in body["findings"]
            ]
            if len(canonical_json_bytes(body["findings"])) > _MAX_FINDINGS_BYTES:
                raise ValueError("review findings exceed aggregate size limit")
        # Validate the body first so bad fields never reach the signature.
        body = ReviewRunnerReceipt.model_validate(
            {**body, "proof": "0" * 64}
        ).model_dump(mode="json", exclude={"proof"})
        proof = self._sign(self._review_secret, body)
        receipt = {**body, "proof": proof}
        ReviewRunnerReceipt.model_validate(receipt)
        return receipt

    def verify_review(self, receipt: dict) -> ReviewRunnerReceipt:
        if receipt.get("receipt_kind", _RECEIPT_KIND_REVIEW) != _RECEIPT_KIND_REVIEW:
            raise AdapterError("INVALID_REQUEST", "receipt kind is not review runner")
        try:
            model = ReviewRunnerReceipt.model_validate(receipt)
        except ValidationError as exc:
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED", "review runner receipt is unsigned"
            ) from exc
        if model.signing_key_id != self.review_key_id:
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED", "review runner signing key is unknown"
            )
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
        body["signing_key_id"] = self.validation_key_id
        body["signing_algorithm"] = SIGNING_ALGORITHM
        body = ValidationRunnerReceipt.model_validate(
            {**body, "proof": "0" * 64}
        ).model_dump(mode="json", exclude={"proof"})
        proof = self._sign(self._validation_secret, body)
        receipt = {**body, "proof": proof}
        ValidationRunnerReceipt.model_validate(receipt)
        return receipt

    def verify_validation(self, receipt: dict) -> ValidationRunnerReceipt:
        if (
            receipt.get("receipt_kind", _RECEIPT_KIND_VALIDATION)
            != _RECEIPT_KIND_VALIDATION
        ):
            raise AdapterError("INVALID_REQUEST", "receipt kind is not validation runner")
        try:
            model = ValidationRunnerReceipt.model_validate(receipt)
        except ValidationError as exc:
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED", "validation runner receipt is unsigned"
            ) from exc
        if model.signing_key_id != self.validation_key_id:
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED",
                "validation runner signing key is unknown",
            )
        expected = self._sign(self._validation_secret, self._body(receipt))
        if not hmac.compare_digest(expected, receipt["proof"]):
            raise AdapterError(
                "RECEIPT_AUTHENTICITY_FAILED",
                "validation runner receipt proof is invalid",
            )
        return model

    def sign_capsule_checkpoint(self, body: dict) -> dict:
        """Return a purpose-separated durable proof over capsule material."""
        return {
            "signing_key_id": self.capsule_key_id,
            "signing_algorithm": SIGNING_ALGORITHM,
            "proof": self._sign(self._capsule_secret, body),
        }

    def verify_capsule_checkpoint(self, body: dict, checkpoint: dict) -> None:
        if (
            checkpoint.get("signing_key_id") != self.capsule_key_id
            or checkpoint.get("signing_algorithm") != SIGNING_ALGORITHM
            or not isinstance(checkpoint.get("proof"), str)
        ):
            raise AdapterError(
                "CAPSULE_AUTHENTICITY_FAILED", "capsule checkpoint key is unknown"
            )
        expected = self._sign(self._capsule_secret, body)
        if not hmac.compare_digest(expected, checkpoint["proof"]):
            raise AdapterError(
                "CAPSULE_AUTHENTICITY_FAILED", "capsule checkpoint proof is invalid"
            )


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
    findings it reported.

    The reviewer runs only in a private standalone Git clone materialized from
    an exact committed-HEAD bundle.  Ignored and dirty files from the source
    worktree are absent, while baseline-to-HEAD history remains available.
    Zero-write is proven by the trusted parent over both that private clone and
    the original worktree/linked Git metadata using complete metadata snapshots
    (type/mode/inode/size/mtime/ctime).  Any change proves a write, including a
    write-and-restore that two Git diffs could not distinguish.  The child has
    no zero-write field because its claim would not be independent evidence.

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
        executable_sha256: str | None = None,
        interpreter_sha256: str | None = None,
        protected_roots: list[Path] | None = None,
        sandbox_launcher: str | None = None,
        sandbox_launcher_sha256: str | None = None,
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
        if not version:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner version is not configured"
            )
        if not identity:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner identity is not configured"
            )
        self.executable = str(resolved)
        observed_sha256 = self._validate_executable()
        if executable_sha256 is not None and not re.fullmatch(_HEX64_RE, executable_sha256):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner SHA-256 is invalid"
            )
        self.executable_sha256 = executable_sha256 or observed_sha256
        if not hmac.compare_digest(self.executable_sha256, observed_sha256):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner identity does not match"
            )
        self.interpreter, self.interpreter_sha256 = self._configure_interpreter(
            interpreter_sha256
        )
        self._protected_roots = self._validate_protected_roots(protected_roots or [])
        self.version = version
        self.identity = identity
        self.timeout_seconds = timeout_seconds
        self._sandbox_launcher, self._sandbox_launcher_sha256 = (
            self._configure_sandbox_launcher(
                sandbox_launcher=sandbox_launcher,
                sandbox_launcher_sha256=sandbox_launcher_sha256,
            )
        )

    @staticmethod
    def _hash_validated_launcher(path: Path, *, expected_uid: int) -> str:
        """Validate a sandbox launcher through a no-follow descriptor and hash it."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "review sandbox launcher could not be opened safely"
            ) from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) not in {0o500, 0o555, 0o700, 0o755}
                or not 1 <= info.st_size <= _MAX_SANDBOX_LAUNCHER_BYTES
            ):
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "review sandbox launcher identity is unsafe"
                )
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 64 * 1024):
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def _configure_sandbox_launcher(
        self,
        *,
        sandbox_launcher: str | None,
        sandbox_launcher_sha256: str | None,
    ) -> tuple[Path | None, str | None]:
        """Pin the macOS sandbox or an explicit non-production test mimic."""
        if sys.platform == "darwin":
            required = Path("/usr/bin/sandbox-exec")
            if sandbox_launcher is not None:
                try:
                    supplied = Path(sandbox_launcher).resolve(strict=True)
                except OSError as exc:
                    raise AdapterError(
                        "CODEX_UNAVAILABLE", "review sandbox launcher is unavailable"
                    ) from exc
                if supplied != required:
                    raise AdapterError(
                        "CODEX_UNAVAILABLE",
                        "Darwin review sandbox launcher must be /usr/bin/sandbox-exec",
                    )
            try:
                resolved = required.resolve(strict=True)
            except OSError as exc:
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "Darwin review sandbox launcher is unavailable"
                ) from exc
            digest = self._hash_validated_launcher(resolved, expected_uid=0)
            if sandbox_launcher_sha256 is not None and not hmac.compare_digest(
                digest, sandbox_launcher_sha256
            ):
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "Darwin review sandbox launcher identity mismatched"
                )
            return resolved, digest

        if sandbox_launcher is None:
            return None, None
        if not sandbox_launcher_sha256 or not re.fullmatch(
            _HEX64_RE, sandbox_launcher_sha256
        ):
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "non-Darwin test sandbox launcher requires a pinned SHA-256",
            )
        try:
            resolved = Path(sandbox_launcher).resolve(strict=True)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "test sandbox launcher is unavailable"
            ) from exc
        digest = self._hash_validated_launcher(
            resolved, expected_uid=_posix_effective_uid()
        )
        if not hmac.compare_digest(digest, sandbox_launcher_sha256):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "test sandbox launcher identity mismatched"
            )
        return resolved, digest

    def _validate_executable(self) -> str:
        """Validate and hash the configured executable without following links."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.executable, flags)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner could not be opened safely"
            ) from exc
        try:
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()  # windows-footgun: ok
                or mode not in {0o500, 0o550, 0o555, 0o700, 0o750, 0o755}
                or not 1 <= info.st_size <= _MAX_EXECUTABLE_BYTES
            ):
                raise AdapterError(
                    "CODEX_UNAVAILABLE",
                    "read-only Codex runner requires an owner-only immutable identity",
                )
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_interpreter(path: Path) -> Path | None:
        """Return a script's absolute interpreter, rejecting env/relative dispatch."""
        try:
            with path.open("rb") as handle:
                first_line = handle.readline(512)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner runtime is unavailable"
            ) from exc
        if not first_line.startswith(b"#!"):
            return None
        try:
            words = first_line[2:].decode("utf-8").strip().split()
            interpreter = Path(words[0])
        except (UnicodeDecodeError, IndexError) as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner shebang is invalid"
            ) from exc
        if not interpreter.is_absolute():
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner shebang is not absolute"
            )
        if interpreter == Path("/usr/bin/env"):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner may not use /usr/bin/env"
            )
        try:
            resolved = interpreter.resolve(strict=True)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner runtime is unavailable"
            ) from exc
        if resolved == Path("/usr/bin/env"):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex runner may not use /usr/bin/env"
            )
        if len(words) != 1:
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "read-only Codex runner shebang arguments are not supported",
            )
        return resolved

    @staticmethod
    def _hash_validated_interpreter(path: Path) -> str:
        """Validate and hash one absolute interpreter through a no-follow fd."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex interpreter could not be opened safely"
            ) from exc
        try:
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            effective_uid = _posix_effective_uid()
            expected_owners = {0, effective_uid}
            service_can_write = info.st_uid == effective_uid and bool(mode & 0o200)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid not in expected_owners
                or mode & 0o022
                or service_can_write
                or not mode & 0o111
                or not 1 <= info.st_size <= _MAX_EXECUTABLE_BYTES
            ):
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "read-only Codex interpreter identity is unsafe"
                )
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 64 * 1024):
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def _configure_interpreter(self, configured_sha256: str | None) -> tuple[Path | None, str | None]:
        interpreter = self._read_interpreter(Path(self.executable))
        if interpreter is None:
            if configured_sha256 is not None:
                raise AdapterError(
                    "CODEX_UNAVAILABLE",
                    "native Codex runner must not configure an interpreter SHA-256",
                )
            return None, None
        if not isinstance(configured_sha256, str) or not re.fullmatch(
            _HEX64_RE, configured_sha256
        ):
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "script Codex runner requires a lowercase interpreter SHA-256",
            )
        observed = self._hash_validated_interpreter(interpreter)
        if not hmac.compare_digest(observed, configured_sha256):
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex interpreter identity does not match"
            )
        return interpreter, configured_sha256

    @staticmethod
    def _validate_protected_roots(roots: list[Path]) -> tuple[Path, ...]:
        """Canonicalize explicit runtime config/state/key roots, fail closed."""
        validated: set[Path] = set()
        for root in roots:
            try:
                resolved = Path(root).resolve(strict=True)
            except OSError as exc:
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "review protected runtime root is unavailable"
                ) from exc
            validated.add(resolved if resolved.is_dir() else resolved.parent)
        return tuple(sorted(validated, key=str))

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
            "sandbox_scope": _SANDBOX_SCOPE,
            "approval_policy": "never",
            "command": " ".join(self._argv()),
        }

    @staticmethod
    def _git_environment() -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }

    @classmethod
    def _committed_head(cls, root: Path) -> str:
        try:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
                timeout=30,
                env=cls._git_environment(),
            )
            head = result.stdout.decode("ascii").strip()
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "review runner cannot resolve committed HEAD"
            ) from exc
        if not re.fullmatch(_SHA_RE, head):
            raise AdapterError("CODEX_UNAVAILABLE", "review runner resolved an invalid HEAD")
        return head

    @classmethod
    def _materialize_head(cls, root: Path, destination: Path, archive: Path) -> str:
        """Build a private standalone Git repo containing only committed HEAD history.

        A Git bundle is used as the archive boundary.  Clone/checkout performs
        Git's own tree validation, avoiding generic archive extraction and its
        symlink/path-traversal hazards.  The clone has its own object database:
        no alternates, worktree links, or references point at the source repo.
        """
        head = cls._committed_head(root)
        try:
            subprocess.run(
                ["/usr/bin/git", "-C", str(root), "bundle", "create", str(archive), "HEAD"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=120,
                env=cls._git_environment(),
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "protocol.file.allow=always",
                    "clone",
                    "--quiet",
                    "--no-checkout",
                    "--no-local",
                    str(archive),
                    str(destination),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=120,
                env=cls._git_environment(),
            )
            subprocess.run(
                ["/usr/bin/git", "-C", str(destination), "checkout", "--quiet", "--detach", head],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
                timeout=120,
                env=cls._git_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "committed tree archive could not be created"
            ) from exc
        if cls._committed_head(destination) != head:
            raise AdapterError("CODEX_UNAVAILABLE", "materialized review HEAD mismatched")
        cls._validate_materialized_links(destination)
        try:
            status = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(destination),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=True,
                timeout=30,
                env=cls._git_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "materialized review tree could not be verified"
            ) from exc
        if status.stdout:
            raise AdapterError("CODEX_UNAVAILABLE", "materialized review tree is not clean")
        return head

    @staticmethod
    def _validate_materialized_links(root: Path) -> None:
        """Reject any committed symlink that can resolve outside the private repo."""
        try:
            candidates = list(root.rglob("*"))
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "materialized review links could not be inspected"
            ) from exc
        for candidate in candidates:
            try:
                info = candidate.lstat()
            except OSError as exc:
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "materialized review links could not be inspected"
                ) from exc
            if not stat.S_ISLNK(info.st_mode):
                continue
            try:
                link_target = os.readlink(candidate)
                if os.path.isabs(link_target):
                    raise ValueError("absolute symlink")
                resolved = (candidate.parent / link_target).resolve(strict=False)
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise AdapterError(
                    "CODEX_UNAVAILABLE",
                    "materialized review tree contains an escaping symlink",
                ) from exc

    def _private_executable(self, directory: Path) -> Path:
        """Copy the pinned executable into the private launch directory."""
        observed = self._validate_executable()
        if not hmac.compare_digest(observed, self.executable_sha256):
            raise AdapterError("CODEX_UNAVAILABLE", "read-only Codex runner identity drifted")
        target = directory / "codex-review"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(target, flags, 0o500)
            source_descriptor = os.open(
                self.executable,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            try:
                source_info = os.fstat(source_descriptor)
                source_mode = stat.S_IMODE(source_info.st_mode)
                if (
                    not stat.S_ISREG(source_info.st_mode)
                    or source_info.st_nlink != 1
                    or source_info.st_uid != os.geteuid()  # windows-footgun: ok
                    or source_mode not in {0o500, 0o550, 0o555, 0o700, 0o750, 0o755}
                    or not 1 <= source_info.st_size <= _MAX_EXECUTABLE_BYTES
                ):
                    raise AdapterError(
                        "CODEX_UNAVAILABLE", "read-only Codex runner identity drifted"
                    )
                copied_digest = hashlib.sha256()
                while True:
                    chunk = os.read(source_descriptor, 64 * 1024)
                    if not chunk:
                        break
                    copied_digest.update(chunk)
                    os.write(descriptor, chunk)
            finally:
                os.close(source_descriptor)
            os.fsync(descriptor)
        except OSError as exc:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "private Codex runner could not be created safely"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if copied_digest.hexdigest() != self.executable_sha256:
            raise AdapterError("CODEX_UNAVAILABLE", "private Codex runner identity drifted")
        return target

    def _private_interpreter(self, directory: Path) -> Path | None:
        """Revalidate an immutable pinned interpreter for the exact launch."""
        del directory  # The root-owned/non-writable source is the immutable equivalent.
        if self.interpreter is None:
            return None
        observed = self._hash_validated_interpreter(self.interpreter)
        if not hmac.compare_digest(observed, self.interpreter_sha256 or ""):
            raise AdapterError("CODEX_UNAVAILABLE", "read-only Codex interpreter identity drifted")
        return self.interpreter

    def _stream_process(
        self,
        *,
        executable: Path,
        interpreter: Path | None,
        prompt: bytes,
        cwd: Path,
        challenge_id: str,
        private_root: Path,
        protected_roots: list[Path],
    ) -> tuple[int, bytes, bytes]:
        """Run with bounded incremental reads and process-group termination."""
        try:
            executable_info = executable.lstat()
        except OSError as exc:
            raise AdapterError("CODEX_UNAVAILABLE", "private Codex runner is unavailable") from exc
        if (
            not stat.S_ISREG(executable_info.st_mode)
            or executable_info.st_nlink != 1
            or executable_info.st_uid != os.geteuid()  # windows-footgun: ok
            or stat.S_IMODE(executable_info.st_mode) != 0o500
            or not 1 <= executable_info.st_size <= _MAX_EXECUTABLE_BYTES
            or hashlib.sha256(executable.read_bytes()).hexdigest()
            != self.executable_sha256
        ):
            raise AdapterError("CODEX_UNAVAILABLE", "private Codex runner identity drifted")
        argv = [str(executable), *self._argv()[1:]]
        if interpreter is not None:
            observed = self._hash_validated_interpreter(interpreter)
            if not hmac.compare_digest(observed, self.interpreter_sha256 or ""):
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "read-only Codex interpreter identity drifted"
                )
            argv = [str(interpreter), *argv]
        runtime_roots = self._script_runtime_roots(
            protected_roots=protected_roots
        )
        if self._sandbox_launcher is not None:
            observed = self._hash_validated_launcher(
                self._sandbox_launcher,
                expected_uid=0 if sys.platform == "darwin" else _posix_effective_uid(),
            )
            if not hmac.compare_digest(observed, self._sandbox_launcher_sha256 or ""):
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "review sandbox launcher identity drifted"
                )
            argv = [
                str(self._sandbox_launcher),
                "-p",
                self._sandbox_profile(
                    private_root=private_root,
                    protected_roots=protected_roots,
                    runtime_roots=runtime_roots,
                ),
                *argv,
            ]
        elif sys.platform == "darwin":
            raise AdapterError(
                "CODEX_UNAVAILABLE", "Darwin review sandbox launcher is unavailable"
            )
        with tempfile.TemporaryFile(dir=private_root) as input_file:
            input_file.write(prompt)
            input_file.seek(0)
            try:
                proc = subprocess.Popen(
                    argv,
                    stdin=input_file,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(cwd),
                    env=self._environment(challenge_id, private_root),
                    start_new_session=True,
                )
            except OSError as exc:
                raise AdapterError(
                    "CODEX_UNAVAILABLE", "read-only Codex review could not be launched"
                ) from exc
            selector = selectors.DefaultSelector()
            assert proc.stdout is not None and proc.stderr is not None
            selector.register(proc.stdout, selectors.EVENT_READ, ("stdout", _MAX_BOUNDARY_STDOUT_BYTES))
            selector.register(proc.stderr, selectors.EVENT_READ, ("stderr", _MAX_BOUNDARY_STDERR_BYTES))
            buffers = {"stdout": bytearray(), "stderr": bytearray()}
            deadline = time.monotonic() + self.timeout_seconds
            failure: str | None = None
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "read-only Codex review timed out"
                        break
                    events = selector.select(min(remaining, 0.25))
                    if not events and proc.poll() is not None:
                        events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
                    for key, _ in events:
                        name, limit = key.data
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffers[name].extend(chunk)
                        if len(buffers[name]) > limit:
                            failure = f"read-only Codex review {name} exceeds size limit"
                            break
                    if failure:
                        break
                if failure:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)  # windows-footgun: ok
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)
                    raise AdapterError("CODEX_UNAVAILABLE", failure)
                return proc.wait(timeout=5), bytes(buffers["stdout"]), bytes(buffers["stderr"])
            finally:
                selector.close()
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)  # windows-footgun: ok
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)

    def _script_runtime_roots(self, *, protected_roots: list[Path]) -> list[Path]:
        """Allow only the pinned interpreter's runtime roots."""
        if self.interpreter is None:
            return []
        interpreter = self.interpreter
        resolved = interpreter
        protected = [root.resolve(strict=True) for root in protected_roots]
        for root in protected:
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            raise AdapterError(
                "CODEX_UNAVAILABLE", "private Codex runner runtime is protected"
            )
        resolved_root = (
            resolved.parent.parent if resolved.parent.name == "bin" else resolved.parent
        )
        return [resolved_root]

    @staticmethod
    def _sandbox_profile(
        *,
        private_root: Path,
        protected_roots: list[Path],
        runtime_roots: list[Path],
    ) -> str:
        """Return a deny-by-default macOS profile for one private review clone.

        This is not whole-host read isolation.  It protects the original
        worktree/Git metadata plus explicitly supplied config, state, and key
        roots; it also denies network access and writes outside the private
        directory.  System/runtime reads remain available for the pinned
        runner to start.
        """
        private_paths = {
            os.path.abspath(private_root),
            str(private_root.resolve(strict=True)),
        }
        system_reads = (
            "/System",
            "/Library",
            "/usr",
            "/bin",
            "/sbin",
            "/opt/homebrew",
            "/private/etc",
            "/private/var/db",
            "/private/var/run",
            "/dev",
            "/etc",
        )

        def quoted(path: str) -> str:
            return json.dumps(path, ensure_ascii=True)

        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-exec)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            # Required non-persistent sink for subprocess/stdin plumbing.
            "(allow file-write* (literal \"/dev/null\"))",
        ]
        for private_path in sorted(private_paths):
            lines.append(f"(allow file-read* (subpath {quoted(private_path)}))")
            lines.append(f"(allow file-write* (subpath {quoted(private_path)}))")
            candidate = Path(private_path)
            for ancestor in (candidate, *candidate.parents):
                lines.append(
                    f"(allow file-read-metadata (literal {quoted(str(ancestor))}))"
                )
        lines.extend(
            f"(allow file-read* (subpath {quoted(path)}))" for path in system_reads
        )
        for root in runtime_roots:
            aliases = {os.path.abspath(root), str(root.resolve(strict=True))}
            for runtime_path in sorted(aliases):
                lines.append(f"(allow file-read* (subpath {quoted(runtime_path)}))")
                candidate = Path(runtime_path)
                for ancestor in (candidate, *candidate.parents):
                    lines.append(
                        f"(allow file-read-metadata (literal {quoted(str(ancestor))}))"
                    )
        denied: set[str] = set()
        for root in protected_roots:
            for candidate in (os.path.abspath(root), str(root.resolve(strict=True))):
                normalized = os.path.normcase(candidate)
                if normalized not in denied:
                    denied.add(normalized)
                    lines.append(
                        f"(deny file-read* (literal {quoted(normalized)}) "
                        f"(subpath {quoted(normalized)}))"
                    )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _environment(challenge_id: str, private_root: Path) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "TMPDIR": str(private_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "HERMES_REVIEW_CHALLENGE_ID": challenge_id,
        }

    @staticmethod
    def _metadata_roots(root: Path) -> list[tuple[str, Path]]:
        """Return worktree and linked Git metadata roots, fail-closed."""
        roots = [("worktree", root)]
        dotgit = root / ".git"
        if dotgit.is_file():
            try:
                marker = dotgit.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN", "review runner cannot inspect Git metadata"
                ) from exc
            if not marker.startswith("gitdir: "):
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN", "review runner found malformed Git metadata"
                )
            gitdir = Path(marker[8:])
            if not gitdir.is_absolute():
                gitdir = dotgit.parent / gitdir
            try:
                gitdir = gitdir.resolve(strict=True)
            except OSError as exc:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN", "review runner cannot resolve Git metadata"
                ) from exc
            roots.append(("gitdir", gitdir))
            commondir_file = gitdir / "commondir"
            if commondir_file.is_file():
                try:
                    commondir = Path(commondir_file.read_text(encoding="utf-8").strip())
                    if not commondir.is_absolute():
                        commondir = gitdir / commondir
                    commondir = commondir.resolve(strict=True)
                except OSError as exc:
                    raise AdapterError(
                        "ZERO_WRITE_UNPROVEN",
                        "review runner cannot resolve common Git metadata",
                    ) from exc
                roots.append(("commondir", commondir))
        return roots

    @staticmethod
    def _tree_snapshot(label: str, root: Path) -> dict[str, tuple]:
        """Snapshot every entry without following symlinks."""
        snapshot: dict[str, tuple] = {}

        def visit(candidate: Path, relpath: str) -> None:
            try:
                info = candidate.lstat()
                link_target = os.readlink(candidate) if stat.S_ISLNK(info.st_mode) else None
            except OSError as exc:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN", "review runner cannot inspect repository state"
                ) from exc
            snapshot[f"{label}:{relpath}"] = (
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                link_target,
            )
            if not stat.S_ISDIR(info.st_mode):
                return
            try:
                children = sorted(candidate.iterdir(), key=lambda item: item.name)
            except OSError as exc:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN", "review runner cannot inspect repository state"
                ) from exc
            for child in children:
                child_rel = child.name if relpath == "." else f"{relpath}/{child.name}"
                visit(child, child_rel)

        visit(root, ".")
        return snapshot

    @classmethod
    def _trusted_snapshot(cls, root: Path) -> dict[str, tuple]:
        snapshot: dict[str, tuple] = {}
        for label, metadata_root in cls._metadata_roots(root):
            snapshot.update(cls._tree_snapshot(label, metadata_root))
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
        del monitor_paths  # compatibility only; trusted proof covers the full repository.
        metadata_roots = self._metadata_roots(root)
        protected_paths = [path for _, path in metadata_roots]
        protected_paths.extend(self._protected_roots)
        protected_paths = list(dict.fromkeys(protected_paths))
        disclosed_paths = {str(path.resolve(strict=True)) for path in protected_paths}
        if any(path in prompt for path in disclosed_paths):
            raise AdapterError(
                "CODEX_UNAVAILABLE",
                "review prompt discloses original repository paths",
            )
        before = self._trusted_snapshot(root)
        with tempfile.TemporaryDirectory(prefix="hermes-codex-review-") as temp_name:
            private_root = Path(temp_name)
            private_root.chmod(0o700)
            materialized = private_root / "tree"
            materialized.mkdir(mode=0o700)
            archive = private_root / "head.bundle"
            head_before = self._materialize_head(root, materialized, archive)
            archive.unlink()
            executable = self._private_executable(private_root)
            interpreter = self._private_interpreter(private_root)
            materialized_before = self._tree_snapshot("materialized", materialized)
            run_error: BaseException | None = None
            try:
                returncode, stdout, _stderr = self._stream_process(
                    executable=executable,
                    interpreter=interpreter,
                    prompt=prompt.encode("utf-8"),
                    cwd=materialized,
                    challenge_id=challenge_id,
                    private_root=private_root,
                    protected_roots=protected_paths,
                )
            except BaseException as exc:
                run_error = exc
            materialized_after = self._tree_snapshot("materialized", materialized)
            after = self._trusted_snapshot(root)
            try:
                head_after = self._committed_head(root)
            except AdapterError as exc:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN",
                    "review runner cannot prove original repository HEAD stability",
                ) from exc
            if before != after or head_before != head_after:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN",
                    "read-only Codex review modified original repository state",
                )
            if materialized_before != materialized_after:
                raise AdapterError(
                    "ZERO_WRITE_UNPROVEN",
                    "read-only Codex review modified materialized committed tree",
                )
            if run_error is not None:
                raise run_error
        if returncode != 0:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex review exited non-zero"
            )
        try:
            raw = json.loads(stdout.decode("utf-8"))
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
        findings_json = canonical_json_bytes(
            [finding.model_dump(mode="json") for finding in boundary.findings]
        )
        if len(findings_json) > _MAX_FINDINGS_BYTES:
            raise AdapterError(
                "CODEX_UNAVAILABLE", "read-only Codex findings exceed size limit"
            )
        return CodexRunResult(
            thread_id=boundary.thread_id,
            response_sha256=sha256_bytes(boundary.response.encode("utf-8")),
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
