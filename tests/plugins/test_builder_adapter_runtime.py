"""Runtime wiring: repository-root fail-closed, shared receipt authority, and
build_runtime-level end-to-end review dispatch."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from plugins.builder_adapter import runtime
from plugins.builder_adapter.errors import AdapterError
from plugins.builder_adapter.review_orchestrator import (
    PHASE_IMPLEMENTING,
    PHASE_REVIEWING,
    PHASE_VERIFYING,
)
from plugins.builder_adapter.runtime import (
    RuntimeSettings,
    _require_repository_roots,
    build_runtime,
)
from plugins.builder_adapter.validation import ValidationRunner


REPOSITORY_ID = "hermes-agent"
BRANCH = "feat/review"
ALLOWED_PATHS = ["plugins/builder_adapter/**"]
_DEFAULT_CODEX_DIGEST = object()


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


def make_git_worktree(tmp_path: Path) -> tuple[Path, str, str]:
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
    _run_git("-C", str(repo), "config", "user.email", "test@example.invalid")
    _run_git("-C", str(repo), "config", "user.name", "Test")
    worktree = base / "wt"
    _run_git(
        "-C", str(repo), "worktree", "add", "-q", "-b", BRANCH, str(worktree), starting_sha
    )
    impl = worktree / "plugins/builder_adapter/impl.py"
    impl.parent.mkdir(parents=True, exist_ok=True)
    impl.write_text("value = 1\n")
    _run_git("-C", str(worktree), "add", "plugins/builder_adapter/impl.py")
    _run_git("-C", str(worktree), "commit", "-qm", "implementation")
    return worktree, starting_sha, str(source)


def create_payload(worktree: Path, starting_sha: str) -> dict:
    return {
        "job_id": str(uuid4()),
        "repository_id": REPOSITORY_ID,
        "worktree_path": str(worktree),
        "branch": BRANCH,
        "starting_sha": starting_sha,
        "allowed_paths": list(ALLOWED_PATHS),
    }


def make_codex_executable(tmp_path: Path) -> str:
    script = tmp_path / "codex-review"
    interpreter = (
        "/Library/Developer/CommandLineTools/usr/bin/python3"
        if sys.platform == "darwin"
        else "/usr/bin/python3"
        if sys.platform.startswith("linux")
        else sys.executable
    )
    script.write_text(
        f"#!{interpreter}\n"
        "import json\n"
        "print(json.dumps({'thread_id': 'thread-1', 'response': 'ok', "
        "'findings': []}))\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


class _FakeSnapshot:
    def __init__(self, profile_id: str):
        self._profile_id = profile_id

    def value(self, artifact_id: str) -> dict:
        if artifact_id == "validation_profile":
            return {"profile_id": self._profile_id, "commands": []}
        return {}

    def raw(self, artifact_id: str) -> bytes:
        # A minimal, valid Draft 2020-12 JSON Schema.  The real
        # GovernanceSnapshot returns the registered artifact bytes; the runtime
        # feeds these straight into SchemaRegistry, which requires a
        # specification-detectable schema (a ``$schema``/``$id``), not ``{}``.
        return json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": f"https://hermes.invalid/schemas/{artifact_id}",
                "type": "object",
            }
        ).encode("utf-8")


def _make_settings(
    tmp_path: Path,
    remote: str,
    *,
    roots=None,
    codex=None,
    codex_sha256=_DEFAULT_CODEX_DIGEST,
):
    profile_id = "hermes-builder-adapter-strict.v1"
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "principal": "orchestrator-mcp",
                        "key_id": "runtime-test-key",
                        "secret_env": "HERMES_BUILDER_ADAPTER_SECRET_RUNTIME",
                        "allowed_uid": os.getuid(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    auth_file.chmod(0o600)
    codex_executable = codex if codex is not None else make_codex_executable(tmp_path)
    config = {
        "socket_path": str(tmp_path / "adapter.sock"),
        "state_path": str(tmp_path / "dispatch.db"),
        "auth_file": str(auth_file),
        "governance_repo": "/opt/bots",
        "governance_commit": "a" * 40,
        "repository_allowlist": {REPOSITORY_ID: remote},
        "validation_profile_id": profile_id,
        "cycle_registry": {},
        "review_state_path": str(tmp_path / "review.db"),
        "repository_roots": roots if roots is not None else [str(tmp_path.resolve())],
        "codex_executable": codex_executable,
        "codex_version": "0.0.0-test",
        "codex_identity": "codex_mcp",
    }
    if codex_sha256 is _DEFAULT_CODEX_DIGEST:
        config["codex_executable_sha256"] = hashlib.sha256(
            Path(codex_executable).read_bytes()
        ).hexdigest()
    elif codex_sha256 is not None:
        config["codex_executable_sha256"] = codex_sha256
    first_line = Path(codex_executable).read_text(encoding="utf-8").splitlines()[0]
    if first_line.startswith("#!"):
        interpreter = Path(first_line[2:].split()[0]).resolve()
        config["codex_interpreter_sha256"] = hashlib.sha256(
            interpreter.read_bytes()
        ).hexdigest()
    config_path = tmp_path / "runtime.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)
    return profile_id, RuntimeSettings.from_file(config_path)


# ── repository-root fail-closed ──────────────────────────────────────────────
def test_require_repository_roots_rejects_omitted_and_empty():
    with pytest.raises(AdapterError) as raised:
        _require_repository_roots([])
    assert raised.value.code == "INVALID_CONFIG"


def test_require_repository_roots_rejects_missing_and_relative(tmp_path):
    with pytest.raises(AdapterError) as raised:
        _require_repository_roots([str(tmp_path / "does-not-exist")])
    assert raised.value.code == "INVALID_CONFIG"
    with pytest.raises(AdapterError) as raised:
        _require_repository_roots(["relative/dir"])
    assert raised.value.code == "INVALID_CONFIG"
    with pytest.raises(AdapterError) as raised:
        _require_repository_roots(["/tmp/root\x00evil"])
    assert raised.value.code == "INVALID_CONFIG"


def test_require_repository_roots_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(AdapterError) as raised:
        _require_repository_roots([str(linked)])
    assert raised.value.code == "INVALID_CONFIG"


def test_require_repository_roots_accepts_valid(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    assert _require_repository_roots([str(root)]) == frozenset({root.resolve()})


def test_build_runtime_fails_closed_without_roots(tmp_path, monkeypatch):
    _worktree, _starting_sha, remote = make_git_worktree(tmp_path)
    profile_id, settings = _make_settings(tmp_path, remote, roots=[])
    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)
    with pytest.raises(AdapterError) as raised:
        build_runtime(settings)
    assert raised.value.code == "INVALID_CONFIG"


@pytest.mark.parametrize("review_state_value", [pytest.param("omitted"), pytest.param(None)])
def test_build_runtime_legacy_config_keeps_review_disabled(
    tmp_path, monkeypatch, review_state_value
):
    config_path = _write_minimal_config(tmp_path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if review_state_value != "omitted":
        config["review_state_path"] = review_state_value
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)

    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "principal": "orchestrator-mcp",
                        "key_id": "runtime-test-key",
                        "secret_env": "HERMES_BUILDER_ADAPTER_SECRET_RUNTIME",
                        "allowed_uid": os.getuid(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    auth_file.chmod(0o600)

    settings = RuntimeSettings.from_file(config_path)
    assert settings.review_state_path is None
    assert settings.repository_roots == []
    assert settings.codex_executable is None
    assert settings.codex_executable_sha256 is None
    assert settings.codex_interpreter_sha256 is None

    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(settings.validation_profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)

    app, schema_temp, review_runtime = build_runtime(settings)
    try:
        assert review_runtime is None
        paths = {
            item.resource.canonical
            for item in app.router.routes()
            if item.resource is not None
        }
        assert not any(path.startswith("/v1/review-jobs") for path in paths)
    finally:
        schema_temp.cleanup()


# ── build_runtime end-to-end review dispatch ────────────────────────────────
@pytest.mark.parametrize(
    "codex_sha256",
    [
        pytest.param(None, id="missing"),
        pytest.param("A" * 64, id="uppercase"),
        pytest.param("0" * 63, id="wrong-length"),
        pytest.param("g" * 64, id="non-hex"),
        pytest.param(123, id="non-string"),
    ],
)
def test_build_runtime_requires_canonical_codex_digest(
    tmp_path, monkeypatch, codex_sha256
):
    _worktree, _starting_sha, remote = make_git_worktree(tmp_path)
    profile_id, settings = _make_settings(
        tmp_path, remote, codex_sha256=codex_sha256
    )
    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)

    with pytest.raises(AdapterError) as raised:
        build_runtime(settings)
    assert raised.value.code == "INVALID_CONFIG"


def test_build_runtime_rejects_codex_digest_mismatch(tmp_path, monkeypatch):
    _worktree, _starting_sha, remote = make_git_worktree(tmp_path)
    profile_id, settings = _make_settings(tmp_path, remote, codex_sha256="0" * 64)
    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)

    with pytest.raises(AdapterError) as raised:
        build_runtime(settings)
    assert raised.value.code == "CODEX_UNAVAILABLE"
    assert "identity does not match" in str(raised.value)


def test_build_runtime_preserves_expected_codex_digest(tmp_path, monkeypatch):
    _worktree, _starting_sha, remote = make_git_worktree(tmp_path)
    profile_id, settings = _make_settings(tmp_path, remote)
    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)

    _app, schema_temp, review_runtime = build_runtime(settings)
    try:
        assert review_runtime is not None
        assert (
            review_runtime._runner.backend.executable_sha256
            == settings.codex_executable_sha256
        )
    finally:
        schema_temp.cleanup()


def test_build_runtime_dispatches_mints_and_accepts_review(tmp_path, monkeypatch):
    worktree, starting_sha, remote = make_git_worktree(tmp_path)
    profile_id, settings = _make_settings(tmp_path, remote)
    monkeypatch.setattr(
        "plugins.builder_adapter.runtime.GovernanceSnapshot",
        lambda repo, commit: _FakeSnapshot(profile_id),
    )
    monkeypatch.setenv("HERMES_BUILDER_ADAPTER_SECRET_RUNTIME", "s" * 32)

    app, schema_temp, review_runtime = build_runtime(settings)
    try:
        assert review_runtime is not None
        orchestrator = review_runtime._orchestrator
        runner = review_runtime._runner
        attestor = review_runtime._attestor

        # Exactly one authority shared by the orchestrator (verifier), the
        # runner (minter), and the attestor (minter).
        assert orchestrator.authority is runner.authority
        assert orchestrator.authority is attestor.authority

        # The attestor consumes the real isolated ValidationRunner, never a
        # caller-authored fake.
        assert isinstance(attestor.validation, ValidationRunner)

        # The HTTP surface exposes submission routes only -- no mint route and
        # no authority/secret.
        paths = {
            item.resource.canonical
            for item in app.router.routes()
            if item.resource is not None
        }
        assert "/v1/review-jobs/{job_id}/review" in paths
        assert "/v1/review-jobs/{job_id}/verification" in paths
        assert not any("mint" in p or "authority" in p or "secret" in p for p in paths)

        payload = create_payload(worktree, starting_sha)
        job_id = payload["job_id"]
        orchestrator.create("hermes", payload)
        orchestrator.transition(
            "hermes", job_id, {"target_phase": PHASE_IMPLEMENTING}
        )
        prompt_text = "review this change"
        prompt_sha256 = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        orchestrator.transition(
            "hermes",
            job_id,
            {"target_phase": PHASE_REVIEWING, "prompt_sha256": prompt_sha256},
        )

        result = review_runtime.run_review(job_id=job_id, prompt=prompt_text)
        assert result["record"]["phase"] == PHASE_VERIFYING
        assert result["receipt"]["proof"]
    finally:
        schema_temp.cleanup()


# ── local operator commands ──────────────────────────────────────────────────
def _write_minimal_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "operator.json"
    config_path.write_text(
        json.dumps(
            {
                "socket_path": str(tmp_path / "adapter.sock"),
                "state_path": str(tmp_path / "dispatch.db"),
                "auth_file": str(tmp_path / "auth.json"),
                "governance_repo": str(tmp_path),
                "governance_commit": "a" * 40,
                "repository_allowlist": {"hermes-agent": str(tmp_path)},
                "validation_profile_id": "hermes-builder-adapter-strict.v1",
                "cycle_registry": {},
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    return config_path


class _FakeSchemaTemp:
    def __init__(self) -> None:
        self.cleaned = False

    def cleanup(self) -> None:
        self.cleaned = True


class _FakeReviewRuntime:
    def __init__(self, *, review_error: AdapterError | None = None) -> None:
        self._review_error = review_error
        self.review_calls: list[tuple[str, str]] = []
        self.validation_calls: list[tuple[str, str, dict, dict]] = []

    def run_review(self, *, job_id: str, prompt: str) -> dict:
        self.review_calls.append((job_id, prompt))
        if self._review_error is not None:
            raise self._review_error
        return {"receipt": {"proof": "a" * 64}, "record": {"phase": "VERIFYING"}}

    def run_validation(
        self, *, job_id: str, profile_id: str, focused_test: dict, full_test: dict
    ) -> dict:
        self.validation_calls.append((job_id, profile_id, focused_test, full_test))
        return {
            "receipt": {"proof": "b" * 64},
            "record": {"phase": "READY_FOR_GPT_VALIDATION"},
        }


# ── argument parsing / dispatch ──────────────────────────────────────────────
def test_main_dispatches_run_review(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("review this", encoding="utf-8")
    prompt_file.chmod(0o600)

    seen: dict = {}

    def fake_run_review(settings, job_id, prompt_file_arg):
        seen["settings"] = settings
        seen["job_id"] = job_id
        seen["prompt_file"] = prompt_file_arg

    monkeypatch.setattr(runtime, "_run_review", fake_run_review)
    rc = runtime.main(
        [
            "run-review",
            "--config",
            str(config_path),
            "--job-id",
            "job-123",
            "--prompt-file",
            str(prompt_file),
        ]
    )
    assert rc == 0
    assert seen["job_id"] == "job-123"
    assert seen["prompt_file"] == prompt_file
    assert isinstance(seen["settings"], RuntimeSettings)


def test_main_dispatches_run_validation(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)

    seen: dict = {}

    def fake_run_validation(settings, job_id, profile_id, focused_file, full_file):
        seen["job_id"] = job_id
        seen["profile_id"] = profile_id
        seen["focused_file"] = focused_file
        seen["full_file"] = full_file

    monkeypatch.setattr(runtime, "_run_validation", fake_run_validation)
    rc = runtime.main(
        [
            "run-validation",
            "--config",
            str(config_path),
            "--job-id",
            "job-456",
            "--profile-id",
            "profile-9",
            "--focused-result-file",
            str(tmp_path / "focused.json"),
            "--full-result-file",
            str(tmp_path / "full.json"),
        ]
    )
    assert rc == 0
    assert seen["job_id"] == "job-456"
    assert seen["profile_id"] == "profile-9"
    assert seen["focused_file"] == tmp_path / "focused.json"
    assert seen["full_file"] == tmp_path / "full.json"


def test_main_rejects_unknown_command():
    with pytest.raises(SystemExit) as raised:
        runtime.main(["frobnicate"])
    assert raised.value.code == 2


def test_main_rejects_missing_prompt_file():
    with pytest.raises(SystemExit) as raised:
        runtime.main(["run-review", "--config", "x", "--job-id", "y"])
    assert raised.value.code == 2


def test_main_adapter_error_is_fail_closed_non_secret(tmp_path, capsys):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "socket_path": str(tmp_path / "sock"),
                "state_path": str(tmp_path / "db"),
                "auth_file": str(tmp_path / "auth"),
                "governance_repo": str(tmp_path),
                "governance_commit": "a" * 40,
                "repository_allowlist": {},
                "validation_profile_id": "p",
                "cycle_registry": {},
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o644)  # group-readable -> unsafe owner-only mode

    rc = runtime.main(
        ["run-review", "--config", str(config_path), "--job-id", "j", "--prompt-file", "p"]
    )
    assert rc == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    err = json.loads(captured.err)
    assert err["code"] == "AUTHORIZATION_FAILED"
    assert "secret" not in captured.err.lower()


# ── secure prompt rejection ──────────────────────────────────────────────────
def test_read_owner_prompt_accepts_valid(tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("review this change", encoding="utf-8")
    prompt_file.chmod(0o600)
    assert runtime._read_owner_prompt(prompt_file) == "review this change"


def test_read_owner_prompt_rejects_symlink(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("prompt", encoding="utf-8")
    real.chmod(0o600)
    linked = tmp_path / "linked.txt"
    linked.symlink_to(real)
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(linked)
    assert raised.value.code == "AUTHORIZATION_FAILED"


def test_read_owner_prompt_rejects_directory(tmp_path):
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(tmp_path)
    assert raised.value.code == "AUTHORIZATION_FAILED"


def test_read_owner_prompt_rejects_unsafe_mode(tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("prompt", encoding="utf-8")
    prompt_file.chmod(0o644)  # group-readable
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(prompt_file)
    assert raised.value.code == "AUTHORIZATION_FAILED"


def test_read_owner_prompt_rejects_invalid_utf8(tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_bytes(b"\xff\xfe\x00")
    prompt_file.chmod(0o600)
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(prompt_file)
    assert raised.value.code == "INVALID_REQUEST"


def test_read_owner_prompt_rejects_empty(tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("   \n", encoding="utf-8")
    prompt_file.chmod(0o600)
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(prompt_file)
    assert raised.value.code == "INVALID_REQUEST"


def test_read_owner_prompt_rejects_oversize(tmp_path):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_bytes(b"x" * (runtime._MAX_PROMPT_BYTES + 1))
    prompt_file.chmod(0o600)
    with pytest.raises(AdapterError) as raised:
        runtime._read_owner_prompt(prompt_file)
    assert raised.value.code == "AUTHORIZATION_FAILED"


# ── runtime absence / cleanup ────────────────────────────────────────────────
def test_run_review_requires_configured_runtime(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)
    settings = RuntimeSettings.from_file(config_path)
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("prompt", encoding="utf-8")
    prompt_file.chmod(0o600)
    schema_temp = _FakeSchemaTemp()
    monkeypatch.setattr(runtime, "build_runtime", lambda s: (None, schema_temp, None))

    with pytest.raises(AdapterError) as raised:
        runtime._run_review(settings, "job", prompt_file)
    assert raised.value.code == "INVALID_CONFIG"
    assert schema_temp.cleaned


def test_run_review_cleans_up_on_success(tmp_path, monkeypatch, capsys):
    config_path = _write_minimal_config(tmp_path)
    settings = RuntimeSettings.from_file(config_path)
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("review this change", encoding="utf-8")
    prompt_file.chmod(0o600)
    schema_temp = _FakeSchemaTemp()
    fake_runtime = _FakeReviewRuntime()
    monkeypatch.setattr(
        runtime, "build_runtime", lambda s: (None, schema_temp, fake_runtime)
    )

    runtime._run_review(settings, "job-123", prompt_file)

    assert schema_temp.cleaned
    assert fake_runtime.review_calls == [("job-123", "review this change")]
    out = capsys.readouterr().out
    assert json.loads(out)["record"]["phase"] == "VERIFYING"
    assert out.strip().count("\n") == 0


def test_run_review_cleans_up_on_exception(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)
    settings = RuntimeSettings.from_file(config_path)
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("prompt", encoding="utf-8")
    prompt_file.chmod(0o600)
    schema_temp = _FakeSchemaTemp()
    fake_runtime = _FakeReviewRuntime(
        review_error=AdapterError("CODEX_UNAVAILABLE", "read-only Codex review timed out")
    )
    monkeypatch.setattr(
        runtime, "build_runtime", lambda s: (None, schema_temp, fake_runtime)
    )

    with pytest.raises(AdapterError) as raised:
        runtime._run_review(settings, "job-123", prompt_file)
    assert raised.value.code == "CODEX_UNAVAILABLE"
    assert schema_temp.cleaned


def test_run_validation_reads_files_and_cleans_up(tmp_path, monkeypatch, capsys):
    config_path = _write_minimal_config(tmp_path)
    settings = RuntimeSettings.from_file(config_path)
    focused_file = tmp_path / "focused.json"
    focused_file.write_text(
        json.dumps(
            {
                "scope": "focused",
                "status": "PASSED",
                "command": "pytest -q",
                "summary": "",
                "ran_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    focused_file.chmod(0o600)
    full_file = tmp_path / "full.json"
    full_file.write_text(
        json.dumps(
            {
                "scope": "full",
                "status": "PASSED",
                "command": "pytest",
                "summary": "",
                "ran_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    full_file.chmod(0o600)
    schema_temp = _FakeSchemaTemp()
    fake_runtime = _FakeReviewRuntime()
    monkeypatch.setattr(
        runtime, "build_runtime", lambda s: (None, schema_temp, fake_runtime)
    )

    runtime._run_validation(settings, "job-456", "profile-9", focused_file, full_file)

    assert schema_temp.cleaned
    job_id, profile_id, focused, full = fake_runtime.validation_calls[0]
    assert job_id == "job-456"
    assert profile_id == "profile-9"
    assert focused["status"] == "PASSED"
    assert full["status"] == "PASSED"
    out = capsys.readouterr().out
    assert json.loads(out)["record"]["phase"] == "READY_FOR_GPT_VALIDATION"


def test_run_validation_rejects_non_owner_result_file(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)
    settings = RuntimeSettings.from_file(config_path)
    focused_file = tmp_path / "focused.json"
    focused_file.write_text('{"scope": "focused"}', encoding="utf-8")
    focused_file.chmod(0o644)  # strict owner-only mode requires exactly 0o600
    full_file = tmp_path / "full.json"
    full_file.write_text('{"scope": "full"}', encoding="utf-8")
    full_file.chmod(0o600)
    schema_temp = _FakeSchemaTemp()
    monkeypatch.setattr(
        runtime, "build_runtime", lambda s: (None, schema_temp, _FakeReviewRuntime())
    )

    with pytest.raises(AdapterError) as raised:
        runtime._run_validation(settings, "job", "profile", focused_file, full_file)
    assert raised.value.code == "AUTHORIZATION_FAILED"
    assert schema_temp.cleaned


# ── serve backward compatibility ─────────────────────────────────────────────
def test_serve_command_no_regression(tmp_path, monkeypatch):
    config_path = _write_minimal_config(tmp_path)

    served: list = []

    async def fake_serve(settings):
        served.append(settings)

    monkeypatch.setattr(runtime, "serve", fake_serve)
    rc = runtime.main(["serve", "--config", str(config_path)])
    assert rc == 0
    assert len(served) == 1
    assert isinstance(served[0], RuntimeSettings)
