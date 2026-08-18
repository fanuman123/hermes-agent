"""Focused security regressions for the concrete Codex review boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.builder_adapter import review_receipts
from plugins.builder_adapter.errors import AdapterError
from plugins.builder_adapter.review_receipts import (
    CodexReviewBackend,
    redact_secrets,
)


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", "--no-pager", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
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
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git("init", "-q", str(root))
    _git("-C", str(root), "config", "user.email", "review@example.invalid")
    _git("-C", str(root), "config", "user.name", "Review Test")
    (root / "review.txt").write_text("baseline\n", encoding="utf-8")
    _git("-C", str(root), "add", "review.txt")
    _git("-C", str(root), "commit", "-qm", "baseline")
    baseline = _git("-C", str(root), "rev-parse", "HEAD")
    (root / "review.txt").write_text("committed\n", encoding="utf-8")
    _git("-C", str(root), "commit", "-qam", "implementation")
    return root, baseline, _git("-C", str(root), "rev-parse", "HEAD")


def _runner(tmp_path: Path, body: str, *, name: str = "codex-test") -> Path:
    path = tmp_path / name
    interpreter = (
        "/Library/Developer/CommandLineTools/usr/bin/python3"
        if sys.platform == "darwin"
        else "/usr/bin/python3"
        if sys.platform.startswith("linux")
        else sys.executable
    )
    path.write_text(f"#!{interpreter}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def _backend(executable: Path, **kwargs) -> CodexReviewBackend:
    interpreter = Path(executable.read_text(encoding="utf-8").splitlines()[0][2:])
    kwargs.setdefault(
        "interpreter_sha256", hashlib.sha256(interpreter.resolve().read_bytes()).hexdigest()
    )
    if sys.platform != "darwin" and "sandbox_launcher" not in kwargs:
        launcher = executable.with_name(f"sandbox-{executable.name}")
        launcher.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "if len(sys.argv) < 4 or sys.argv[1] != '-p':\n"
            "    raise SystemExit(97)\n"
            "os.execv(sys.argv[3], sys.argv[3:])\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        kwargs["sandbox_launcher"] = str(launcher)
        kwargs["sandbox_launcher_sha256"] = hashlib.sha256(
            launcher.read_bytes()
        ).hexdigest()
    return CodexReviewBackend(
        executable=str(executable),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        version="test",
        identity="codex_mcp",
        **kwargs,
    )


def test_review_uses_standalone_exact_committed_history(tmp_path):
    root, baseline, head = _repo(tmp_path)
    (root / "review.txt").write_text("dirty-secret\n", encoding="utf-8")
    (root / "ignored-secret").write_text("ignored-secret\n", encoding="utf-8")
    executable = _runner(
        tmp_path,
        "import json, pathlib, subprocess, sys\n"
        "sys.stdin.read()\n"
        "root = pathlib.Path.cwd()\n"
        "head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], text=True).strip()\n"
        f"baseline = {baseline!r}\n"
        "history = subprocess.check_output(['/usr/bin/git', 'rev-list', f'{baseline}..HEAD'], text=True).splitlines()\n"
        "ok = ((root / 'review.txt').read_text() == 'committed\\n' and "
        "not (root / 'ignored-secret').exists() and (root / '.git').is_dir() and len(history) == 1)\n"
        "print(json.dumps({'thread_id': 'thread-1', 'response': f'{head}:{ok}', 'findings': []}))\n",
    )
    result = _backend(executable).run(
        prompt="review relative to the current directory",
        cwd=root,
        challenge_id="c" * 64,
    )
    assert result.response_sha256
    assert _git("-C", str(root), "rev-parse", "HEAD") == head
    assert (root / "review.txt").read_text(encoding="utf-8") == "dirty-secret\n"


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox")
def test_macos_sandbox_confines_reads_to_private_clone(tmp_path):
    root, _, _ = _repo(tmp_path)
    (root / ".gitignore").write_text("ignored-secret\n", encoding="utf-8")
    _git("-C", str(root), "add", ".gitignore")
    _git("-C", str(root), "commit", "-qm", "ignore local secret")
    secret = root / "ignored-secret"
    secret.write_text("original-only-secret\n", encoding="utf-8")
    exact = str(secret)
    traversal = str(root / ".." / root.name / "ignored-secret")
    executable = _runner(
        tmp_path,
        "import json, pathlib, sys\n"
        "sys.stdin.read()\n"
        "private_ok = pathlib.Path('review.txt').read_text() == 'committed\\n'\n"
        f"attempts = [{exact!r}, {traversal!r}]\n"
        "blocked = []\n"
        "for candidate in attempts:\n"
        "    try:\n"
        "        pathlib.Path(candidate).read_bytes()\n"
        "    except OSError:\n"
        "        blocked.append(True)\n"
        "    else:\n"
        "        blocked.append(False)\n"
        "confined = private_ok and blocked == [True, True]\n"
        "print(json.dumps({'thread_id': 'confined' if confined else 'escaped', "
        "'response': 'ok', 'findings': []}))\n",
    )
    result = _backend(executable).run(
        prompt="review the committed private clone",
        cwd=root,
        challenge_id="c" * 64,
    )
    assert result.thread_id == "confined"
    assert secret.read_text(encoding="utf-8") == "original-only-secret\n"


def test_explicit_trusted_provider_mode_is_signed_and_runs_without_outer_sandbox(
    tmp_path,
):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path,
        "import json, sys\nsys.stdin.read()\n"
        "print(json.dumps({'thread_id': 'trusted-provider', 'response': 'ok', "
        "'findings': []}))\n",
    )
    backend = _backend(executable, trusted_provider=True)
    result = backend.run(
        prompt="review", cwd=root, challenge_id="c" * 64
    )
    assert result.thread_id == "trusted-provider"
    assert backend.invocation()["sandbox_scope"] == (
        "parent_proves_original_worktree_git_metadata_and_private_clone_zero_write;"
        "trusted_provider_has_network_credentials_and_host_capability"
    )


def test_trusted_provider_mode_must_be_boolean(tmp_path):
    executable = _runner(tmp_path, "raise SystemExit(99)\n")
    with pytest.raises(AdapterError, match="must be boolean"):
        _backend(executable, trusted_provider="yes")


def test_thread_id_is_redacted_at_the_boundary(tmp_path):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path,
        "import json, sys\nsys.stdin.read()\n"
        "print(json.dumps({'thread_id': 'token=thread-secret', 'response': 'ok', 'findings': []}))\n",
    )
    result = _backend(executable).run(
        prompt="review", cwd=root, challenge_id="c" * 64
    )
    assert result.thread_id == "token=[REDACTED]"


def test_materialized_tree_write_then_restore_fails_zero_write_proof(tmp_path):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path,
        "import json, pathlib, sys\nsys.stdin.read()\n"
        "path = pathlib.Path('review.txt')\n"
        "original = path.read_bytes()\n"
        "path.write_bytes(b'temporary write\\n')\n"
        "path.write_bytes(original)\n"
        "print(json.dumps({'thread_id': 'thread-1', 'response': 'ok', 'findings': []}))\n",
    )
    with pytest.raises(AdapterError) as raised:
        _backend(executable).run(
            prompt="review", cwd=root, challenge_id="c" * 64
        )
    assert raised.value.code == "ZERO_WRITE_UNPROVEN"


def test_prompt_cannot_disclose_original_repository_paths(tmp_path):
    root, _, _ = _repo(tmp_path)
    marker = tmp_path / "executed"
    executable = _runner(
        tmp_path,
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
    )
    with pytest.raises(AdapterError, match="discloses original"):
        _backend(executable).run(
            prompt=f"inspect {root}", cwd=root, challenge_id="c" * 64
        )
    assert not marker.exists()


def test_escaping_committed_symlink_is_rejected(tmp_path):
    root, _, _ = _repo(tmp_path)
    (root / "escape").symlink_to("../../outside-secret")
    _git("-C", str(root), "add", "escape")
    _git("-C", str(root), "commit", "-qm", "escaping symlink")
    executable = _runner(tmp_path, "raise SystemExit(99)\n")
    with pytest.raises(AdapterError, match="escaping symlink"):
        _backend(executable).run(prompt="review", cwd=root, challenge_id="c" * 64)


def test_executable_identity_is_pinned_and_revalidated(tmp_path):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path,
        "import json, sys\nsys.stdin.read()\n"
        "print(json.dumps({'thread_id': 'thread-1', 'response': 'ok', 'findings': []}))\n",
    )
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    interpreter = Path(executable.read_text(encoding="utf-8").splitlines()[0][2:]).resolve()
    interpreter_digest = hashlib.sha256(interpreter.read_bytes()).hexdigest()
    with pytest.raises(AdapterError, match="identity does not match"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256="0" * 64,
            interpreter_sha256=interpreter_digest,
            version="test",
            identity="codex_mcp",
        )
    backend = CodexReviewBackend(
        executable=str(executable),
        executable_sha256=digest,
        interpreter_sha256=interpreter_digest,
        version="test",
        identity="codex_mcp",
    )
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    with pytest.raises(AdapterError, match="identity drifted"):
        backend.run(prompt="review", cwd=root, challenge_id="c" * 64)


@pytest.mark.parametrize("shebang", ["#!/usr/bin/env python3", "#!python3"])
def test_script_runner_rejects_env_and_relative_shebangs(tmp_path, shebang):
    executable = tmp_path / "codex-bad-shebang"
    executable.write_text(f"{shebang}\nraise SystemExit(0)\n", encoding="utf-8")
    executable.chmod(0o500)
    with pytest.raises(AdapterError, match="/usr/bin/env|not absolute"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            interpreter_sha256="0" * 64,
            version="test",
            identity="codex_mcp",
        )


@pytest.mark.parametrize("argument", ["-I", "-e"])
def test_script_runner_rejects_argument_bearing_shebang(tmp_path, argument):
    interpreter = Path(sys.executable).resolve()
    executable = tmp_path / "codex-shebang-argument"
    executable.write_text(
        f"#!{interpreter} {argument}\nraise SystemExit(0)\n", encoding="utf-8"
    )
    executable.chmod(0o500)
    with pytest.raises(AdapterError, match="shebang arguments are not supported"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            interpreter_sha256=hashlib.sha256(interpreter.read_bytes()).hexdigest(),
            version="test",
            identity="codex_mcp",
        )


def test_script_runner_rejects_alias_to_env(tmp_path):
    env_alias = tmp_path / "env-alias"
    env_alias.symlink_to("/usr/bin/env")
    executable = tmp_path / "codex-env-alias"
    executable.write_text(f"#!{env_alias}\n", encoding="utf-8")
    executable.chmod(0o500)
    with pytest.raises(AdapterError, match="may not use /usr/bin/env"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            interpreter_sha256="0" * 64,
            version="test",
            identity="codex_mcp",
        )


def test_script_runner_requires_and_pins_interpreter(tmp_path):
    executable = _runner(tmp_path, "raise SystemExit(0)\n")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    with pytest.raises(AdapterError, match="requires a lowercase interpreter"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256=digest,
            version="test",
            identity="codex_mcp",
        )
    with pytest.raises(AdapterError, match="interpreter identity does not match"):
        CodexReviewBackend(
            executable=str(executable),
            executable_sha256=digest,
            interpreter_sha256="0" * 64,
            version="test",
            identity="codex_mcp",
        )


def test_posix_effective_uid_fails_closed_when_unavailable(monkeypatch):
    monkeypatch.delattr(review_receipts.os, "geteuid")

    with pytest.raises(
        AdapterError, match="POSIX effective-user identity checks are unavailable"
    ):
        review_receipts._posix_effective_uid()


def test_invocation_describes_honest_sandbox_scope(tmp_path):
    executable = _runner(tmp_path, "raise SystemExit(0)\n")
    invocation = _backend(executable).invocation()
    assert invocation["sandbox_scope"].endswith("not_whole_host_read_isolation")


def test_sandbox_explicitly_denies_protected_root_after_broad_allow(tmp_path):
    private_root = tmp_path / "private"
    private_root.mkdir()
    protected = private_root / "runtime-secrets"
    protected.mkdir()
    profile = CodexReviewBackend._sandbox_profile(
        private_root=private_root,
        protected_roots=[protected],
        runtime_roots=[],
    )
    broad_allow = f'(allow file-read* (subpath "{private_root}"))'
    explicit_deny = f'(deny file-read* (literal "{protected}") (subpath "{protected}"))'
    assert broad_allow in profile
    assert explicit_deny in profile
    assert profile.index(explicit_deny) > profile.index(broad_allow)


@pytest.mark.parametrize("descriptor,name", [(1, "stdout"), (2, "stderr")])
def test_stream_caps_terminate_unbounded_reviewer(tmp_path, descriptor, name):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path,
        "import os, sys, time\nsys.stdin.read()\n"
        f"os.write({descriptor}, b'x' * (512 * 1024))\ntime.sleep(30)\n",
        name=f"codex-{name}",
    )
    with pytest.raises(AdapterError, match=f"{name} exceeds"):
        _backend(executable, timeout_seconds=10).run(
            prompt="review", cwd=root, challenge_id="c" * 64
        )


def test_timeout_terminates_reviewer_process_group(tmp_path):
    root, _, _ = _repo(tmp_path)
    executable = _runner(
        tmp_path, "import sys, time\nsys.stdin.read()\ntime.sleep(30)\n"
    )
    with pytest.raises(AdapterError, match="timed out"):
        _backend(executable, timeout_seconds=1).run(
            prompt="review", cwd=root, challenge_id="c" * 64
        )


def test_expanded_secret_redaction_is_idempotent():
    values = [
        "AWS_SECRET_ACCESS_KEY=very-secret-value",
        "DATABASE_PASSWORD=database-password-value",
        "https://alice:password@example.invalid/path",
        "Cookie: session=secret-cookie",
        "Proxy-Authorization: Basic opaque-credential",
        "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
        "github_pat_1234567890abcdef",
        "sk-proj-1234567890abcdef",
        "xoxb-1234567890abcdef",
    ]
    for value in values:
        redacted = redact_secrets(value)
        assert "[REDACTED]" in redacted
        assert redact_secrets(redacted) == redacted
