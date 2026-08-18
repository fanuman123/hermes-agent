"""Explicit, non-auto-starting Hermes-owned adapter runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import stat
import sys
import tempfile
import re
from dataclasses import dataclass
from pathlib import Path

from .adapter import BuilderDispatchAdapter
from .attestation import GovernanceSnapshot, HermesProfileResolver
from .auth import HMACAuthenticator, PrincipalKey, darwin_peer_credentials
from .errors import AdapterError
from .gitops import GitVerifier
from .native import NativeKanbanBackend
from .review_orchestrator import ReviewOrchestrator, ReviewStore
from .review_receipts import CodexReviewBackend, ReceiptAuthority, ReviewRunner, ValidationAttestor
from .review_runtime import ReviewRuntime
from .schemas import SchemaRegistry
from .service import BuilderAdapterService, serve_until
from .store import DispatchStore
from .validation import ValidationRunner


SCHEMA_PATHS = {
    "dispatch_request": "contracts/schemas/hermes-builder-dispatch-request-v1.json",
    "dispatch_result": "contracts/schemas/hermes-builder-dispatch-result-v1.json",
    "completion_evidence": "contracts/schemas/hermes-builder-completion-evidence-v1.json",
    "allowed_manifest": "contracts/schemas/allowed-path-manifest-v1.json",
}


@dataclass(frozen=True)
class RuntimeSettings:
    socket_path: Path
    state_path: Path
    auth_file: Path
    governance_repo: Path
    governance_commit: str
    repository_allowlist: dict[str, str]
    validation_profile_id: str
    board: str
    cycle_registry: dict[str, dict]
    validation_docker_binary: str | None
    validation_docker_host: str | None
    validation_image_id: str | None
    review_state_path: Path | None
    repository_roots: list[str]
    codex_executable: str | None
    codex_version: str | None
    codex_identity: str | None
    codex_timeout_seconds: int | None

    @classmethod
    def from_file(cls, path: str | Path) -> "RuntimeSettings":
        value = _read_owner_json(Path(path), exact_mode=None)
        review_state_path = value.get("review_state_path")
        if review_state_path is None:
            review_state_path = str(Path(value["state_path"]).parent / "review_jobs.db")
        return cls(
            socket_path=Path(value["socket_path"]),
            state_path=Path(value["state_path"]),
            auth_file=Path(value["auth_file"]),
            governance_repo=Path(value["governance_repo"]),
            governance_commit=value["governance_commit"],
            repository_allowlist=dict(value["repository_allowlist"]),
            validation_profile_id=value["validation_profile_id"],
            board=value.get("board", "governed-builder"),
            cycle_registry=dict(value["cycle_registry"]),
            validation_docker_binary=value.get("validation_docker_binary"),
            validation_docker_host=value.get("validation_docker_host"),
            validation_image_id=value.get("validation_image_id"),
            review_state_path=Path(review_state_path),
            repository_roots=[str(item) for item in value.get("repository_roots", [])],
            codex_executable=value.get("codex_executable"),
            codex_version=value.get("codex_version"),
            codex_identity=value.get("codex_identity"),
            codex_timeout_seconds=value.get("codex_timeout_seconds"),
        )


def _read_owner_json(path: Path, *, exact_mode: int | None) -> dict:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if (
            info.st_uid != os.geteuid()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > 1_000_000
            or (
                exact_mode is None
                and stat.S_IMODE(info.st_mode) & 0o077
            )
            or (
                exact_mode is not None
                and stat.S_IMODE(info.st_mode) != exact_mode
            )
        ):
            raise AdapterError(
                "AUTHORIZATION_FAILED", "owner-only configuration file required"
            )
        chunks = []
        remaining = 1_000_001
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise AdapterError(
            "AUTHORIZATION_FAILED", "configuration file could not be opened safely"
        ) from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("INVALID_REQUEST", "invalid configuration JSON") from exc
    if not isinstance(value, dict):
        raise AdapterError("INVALID_REQUEST", "configuration must be an object")
    return value


_MAX_PROMPT_BYTES = 1_000_000


def _read_owner_prompt(path: Path) -> str:
    """Read an operator-controlled prompt file, failing closed on any unsafe
    ownership/type/mode or on invalid UTF-8, empty, or oversize content.

    Prompt text is never accepted on the command line: it must arrive through
    this owner-only, non-symlink, regular-file boundary.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if (
            info.st_uid != os.geteuid()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > _MAX_PROMPT_BYTES
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise AdapterError(
                "AUTHORIZATION_FAILED", "owner-only regular prompt file required"
            )
        chunks = []
        remaining = _MAX_PROMPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise AdapterError(
            "AUTHORIZATION_FAILED", "prompt file could not be opened safely"
        ) from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError("INVALID_REQUEST", "prompt file is not valid UTF-8") from exc
    if not text.strip():
        raise AdapterError("INVALID_REQUEST", "prompt file is empty")
    return text


def _load_keys(path: Path) -> list[PrincipalKey]:
    value = _read_owner_json(path, exact_mode=0o600)
    keys = []
    for item in value.get("keys", []):
        secret_env = item["secret_env"]
        if not re.fullmatch(r"HERMES_BUILDER_ADAPTER_SECRET_[A-Z0-9_]+", secret_env):
            raise AdapterError(
                "AUTHORIZATION_FAILED", "unapproved secret source identifier"
            )
        secret = os.environ.get(secret_env)
        if not secret:
            raise AdapterError(
                "AUTHENTICATION_FAILED",
                f"approved secret source did not supply {secret_env}",
            )
        keys.append(
            PrincipalKey(
                principal=item["principal"],
                key_id=item["key_id"],
                secret=secret.encode(),
                allowed_uid=int(item["allowed_uid"]),
                allowed_gid=(
                    int(item["allowed_gid"])
                    if item.get("allowed_gid") is not None
                    else None
                ),
                active=bool(item.get("active", True)),
            )
        )
    if not keys:
        raise AdapterError("AUTHENTICATION_FAILED", "no authorized principals")
    return keys


def _require_repository_roots(roots: list[str]) -> frozenset[Path]:
    """Fail closed on an empty/missing/invalid canonical repository-root set.

    When review orchestration is enabled, at least one canonical, existing,
    non-symlink absolute directory is required so worktree containment cannot
    be silently disabled.
    """
    if not roots:
        raise AdapterError(
            "INVALID_CONFIG",
            "review orchestration requires at least one canonical repository root",
        )
    resolved: set[Path] = set()
    for raw in roots:
        if not raw or "\x00" in raw:
            raise AdapterError("INVALID_CONFIG", "repository root is empty or NUL")
        candidate = Path(raw)
        if not candidate.is_absolute():
            raise AdapterError("INVALID_CONFIG", "repository root must be absolute")
        try:
            real = candidate.resolve(strict=True)
        except OSError as exc:
            raise AdapterError("INVALID_CONFIG", "repository root does not exist") from exc
        if real != candidate or candidate.is_symlink():
            raise AdapterError("INVALID_CONFIG", "repository root is not canonical")
        if not real.is_dir():
            raise AdapterError("INVALID_CONFIG", "repository root is not a directory")
        resolved.add(real)
    if not resolved:
        raise AdapterError("INVALID_CONFIG", "no valid repository roots")
    return frozenset(resolved)


def build_runtime(settings: RuntimeSettings):
    # Repository-root containment is a precondition for review orchestration.
    # Validate it before any governance/schema/store construction so an empty
    # or invalid root set fails closed deterministically, independent of
    # governance-commit or schema-validator availability.
    repository_roots = None
    if settings.review_state_path is not None:
        repository_roots = _require_repository_roots(settings.repository_roots)

    snapshot = GovernanceSnapshot(settings.governance_repo, settings.governance_commit)
    validation_profile = snapshot.value("validation_profile")
    if validation_profile.get("profile_id") != settings.validation_profile_id:
        raise AdapterError(
            "MANIFEST_MISMATCH", "runtime validation profile ID is not registered"
        )
    git = GitVerifier(settings.repository_allowlist)
    schema_temp = tempfile.TemporaryDirectory(prefix="hermes-builder-schemas-")
    schema_root = Path(schema_temp.name)
    schema_files = {}
    schema_artifacts = {
        "dispatch_request": "dispatch_request_schema",
        "dispatch_result": "dispatch_result_schema",
        "completion_evidence": "completion_evidence_schema",
        "allowed_manifest": "allowed_path_manifest_schema",
    }
    for name, artifact_id in schema_artifacts.items():
        destination = schema_root / f"{name}.json"
        destination.write_bytes(snapshot.raw(artifact_id))
        schema_files[name] = destination
    schemas = SchemaRegistry(schema_files)
    store = DispatchStore(settings.state_path)
    validation = ValidationRunner(
        {settings.validation_profile_id: validation_profile},
        python=sys.executable,
        docker=settings.validation_docker_binary,
        docker_host=settings.validation_docker_host,
        image_id=settings.validation_image_id,
    )
    adapter = BuilderDispatchAdapter(
        store=store,
        schemas=schemas,
        git=git,
        kanban=NativeKanbanBackend(board=settings.board),
        validation=validation,
        governance_repo=settings.governance_repo,
        governance_attestor=snapshot,
        profile_resolver=HermesProfileResolver(),
        cycle_registry=settings.cycle_registry,
    )
    auth = HMACAuthenticator(_load_keys(settings.auth_file), store)
    review_orchestrator = None
    review_runtime = None
    if settings.review_state_path is not None:
        # Exactly one authority is shared by the orchestrator (which verifies)
        # and the runner/attestor (which mint).  Containment and the concrete
        # Codex backend are required; fail closed if they are not configured.
        authority = ReceiptAuthority()
        review_orchestrator = ReviewOrchestrator(
            ReviewStore(settings.review_state_path),
            git=git,
            authority=authority,
            repository_roots=repository_roots,
        )
        codex_backend = CodexReviewBackend(
            executable=settings.codex_executable or "",
            version=settings.codex_version or "",
            identity=settings.codex_identity or "codex_mcp",
            timeout_seconds=settings.codex_timeout_seconds or 1800,
        )
        runner = ReviewRunner(git, authority, codex_backend)
        attestor = ValidationAttestor(
            git,
            authority,
            validation,
            {settings.validation_profile_id: validation_profile},
        )
        review_runtime = ReviewRuntime(review_orchestrator, runner, attestor)
    service = BuilderAdapterService(
        adapter,
        auth,
        peer_resolver=darwin_peer_credentials,
        orchestrator=review_orchestrator,
    )
    return service.application(), schema_temp, review_runtime


async def serve(settings: RuntimeSettings) -> None:
    app, schema_temp, _review_runtime = build_runtime(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals = _install_shutdown_handlers(loop, stop)
    try:
        await serve_until(app, settings.socket_path, stop)
    finally:
        for signum in installed_signals:
            loop.remove_signal_handler(signum)
        schema_temp.cleanup()


def _install_shutdown_handlers(loop, stop: asyncio.Event) -> tuple[signal.Signals, ...]:
    """Turn supervisor termination into an orderly UDS cleanup."""
    installed = []
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except (NotImplementedError, RuntimeError):
            continue
        installed.append(signum)
    return tuple(installed)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m plugins.builder_adapter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser(
        "serve", help="Run the governed builder adapter service over its Unix socket."
    )
    serve_parser.add_argument("--config", required=True, help="runtime settings JSON file")

    review_parser = subparsers.add_parser(
        "run-review", help="Mint a review receipt for an active review challenge."
    )
    review_parser.add_argument("--config", required=True, help="runtime settings JSON file")
    review_parser.add_argument("--job-id", required=True, help="review job id")
    review_parser.add_argument("--prompt-file", required=True, help="owner-only prompt file")

    validation_parser = subparsers.add_parser(
        "run-validation",
        help="Mint a validation receipt for an active verification challenge.",
    )
    validation_parser.add_argument("--config", required=True, help="runtime settings JSON file")
    validation_parser.add_argument("--job-id", required=True, help="review job id")
    validation_parser.add_argument("--profile-id", required=True, help="validation profile id")
    validation_parser.add_argument(
        "--focused-result-file", required=True, help="owner-only focused result JSON file"
    )
    validation_parser.add_argument(
        "--full-result-file", required=True, help="owner-only full result JSON file"
    )

    return parser


def _run_review(settings: RuntimeSettings, job_id: str, prompt_file: Path) -> None:
    _app, schema_temp, review_runtime = build_runtime(settings)
    try:
        if review_runtime is None:
            raise AdapterError("INVALID_CONFIG", "review runtime is not configured")
        prompt = _read_owner_prompt(prompt_file)
        result = review_runtime.run_review(job_id=job_id, prompt=prompt)
        print(json.dumps(result), flush=True)
    finally:
        schema_temp.cleanup()


def _run_validation(
    settings: RuntimeSettings,
    job_id: str,
    profile_id: str,
    focused_file: Path,
    full_file: Path,
) -> None:
    _app, schema_temp, review_runtime = build_runtime(settings)
    try:
        if review_runtime is None:
            raise AdapterError("INVALID_CONFIG", "review runtime is not configured")
        focused_test = _read_owner_json(focused_file, exact_mode=0o600)
        full_test = _read_owner_json(full_file, exact_mode=0o600)
        result = review_runtime.run_validation(
            job_id=job_id,
            profile_id=profile_id,
            focused_test=focused_test,
            full_test=full_test,
        )
        print(json.dumps(result), flush=True)
    finally:
        schema_temp.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        settings = RuntimeSettings.from_file(args.config)
        if args.command == "serve":
            asyncio.run(serve(settings))
            return 0
        if args.command == "run-review":
            _run_review(settings, args.job_id, Path(args.prompt_file))
            return 0
        if args.command == "run-validation":
            _run_validation(
                settings,
                args.job_id,
                args.profile_id,
                Path(args.focused_result_file),
                Path(args.full_result_file),
            )
            return 0
    except AdapterError as exc:
        print(json.dumps(exc.as_dict()), file=sys.stderr, flush=True)
        return 1
    return 0
