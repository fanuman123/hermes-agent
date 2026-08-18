"""Argument-safe Git and governed-path verification."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath

from .errors import AdapterError


def _run_git(
    repo: Path,
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
) -> subprocess.CompletedProcess:
    safe_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "12",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_CONFIG_KEY_1": "commit.gpgSign",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "tag.gpgSign",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "credential.helper",
        "GIT_CONFIG_VALUE_3": "",
        "GIT_CONFIG_KEY_4": "diff.external",
        "GIT_CONFIG_VALUE_4": "",
        "GIT_CONFIG_KEY_5": "core.attributesFile",
        "GIT_CONFIG_VALUE_5": "/dev/null",
        "GIT_CONFIG_KEY_6": "protocol.file.allow",
        "GIT_CONFIG_VALUE_6": "never",
        "GIT_CONFIG_KEY_7": "interactive.diffFilter",
        "GIT_CONFIG_VALUE_7": "",
        "GIT_CONFIG_KEY_8": "core.fsmonitor",
        "GIT_CONFIG_VALUE_8": "false",
        "GIT_CONFIG_KEY_9": "gpg.program",
        "GIT_CONFIG_VALUE_9": "/bin/false",
        "GIT_CONFIG_KEY_10": "gpg.ssh.program",
        "GIT_CONFIG_VALUE_10": "/bin/false",
        "GIT_CONFIG_KEY_11": "core.sshCommand",
        "GIT_CONFIG_VALUE_11": "/bin/false",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
    }
    if env:
        safe_env.update(
            {
                key: value
                for key, value in env.items()
                if not key.startswith("GIT_")
                or key
                in {
                    "GIT_INDEX_FILE",
                    "GIT_AUTHOR_NAME",
                    "GIT_AUTHOR_EMAIL",
                    "GIT_COMMITTER_NAME",
                    "GIT_COMMITTER_EMAIL",
                    "GIT_AUTHOR_DATE",
                    "GIT_COMMITTER_DATE",
                }
            }
        )
    return subprocess.run(
        ["/usr/bin/git", "--no-pager", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=False,
        timeout=30,
        env=safe_env,
        input=input,
    )


def safe_relative_path(raw: str) -> str:
    if not raw or raw.startswith(("/", "\\")) or "\\" in raw or "\x00" in raw:
        raise AdapterError("MANIFEST_MISMATCH", "unsafe governed path")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise AdapterError("MANIFEST_MISMATCH", "unsafe governed path")
    return path.as_posix()


class AllowedPathManifest:
    def __init__(self, value: dict):
        if value.get("default_access") != "forbidden":
            raise AdapterError("MANIFEST_MISMATCH", "manifest must deny by default")
        if value.get("symlinks") != "reject" or value.get("submodules") != "reject":
            raise AdapterError(
                "MANIFEST_MISMATCH", "manifest must reject symlinks and submodules"
            )
        self.base_sha = value["base_sha"]
        read_policy = value.get("read_policy")
        if (
            not isinstance(read_policy, dict)
            or read_policy.get("source") != "git_tracked_regular_files"
            or read_policy.get("snapshot") != "base_sha"
            or not isinstance(read_policy.get("deny_patterns"), list)
            or not read_policy["deny_patterns"]
        ):
            raise AdapterError("MANIFEST_MISMATCH", "tracked read policy is required")
        self.read_denied_patterns = tuple(read_policy["deny_patterns"])
        self.patterns = [
            rule["pattern"]
            for rule in value["rules"]
            if rule.get("access") == "read_write"
        ]

    def permits(self, raw: str) -> bool:
        path = safe_relative_path(raw)
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.patterns)

    def permits_read(self, raw: str) -> bool:
        path = safe_relative_path(raw)
        return not any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in self.read_denied_patterns
        )


class GitVerifier:
    def __init__(self, repository_allowlist: dict[str, str]):
        self._allowlist = repository_allowlist

    def artifact_bytes(self, repo: Path, commit: str, path: str) -> bytes:
        safe_relative_path(path)
        try:
            return _run_git(repo, "cat-file", "blob", f"{commit}:{path}").stdout
        except subprocess.CalledProcessError as exc:
            raise AdapterError(
                "CONTRACT_MISMATCH", "governed artifact is unavailable"
            ) from exc

    def verify_artifact(self, repo: Path, ref, code: str) -> bytes:
        raw = self.artifact_bytes(repo, ref.commit, ref.path)
        if hashlib.sha256(raw).hexdigest() != ref.sha256:
            raise AdapterError(code, "governed artifact hash mismatch")
        return raw

    def verify_worktree(self, request, *, require_clean: bool = True) -> Path:
        expected_remote = self._allowlist.get(request.repository.repository_id)
        if expected_remote != request.repository.canonical_remote:
            raise AdapterError("REPOSITORY_MISMATCH", "repository is not allowlisted")
        root = Path(request.worktree_path)
        try:
            real = root.resolve(strict=True)
        except OSError as exc:
            raise AdapterError("WORKTREE_MISMATCH", "worktree does not exist") from exc
        if real != root or root.is_symlink():
            raise AdapterError("WORKTREE_MISMATCH", "worktree path is not canonical")
        try:
            inside = _run_git(root, "rev-parse", "--is-inside-work-tree").stdout.strip()
            common_raw = _run_git(root, "rev-parse", "--git-common-dir").stdout
            git_dir_raw = _run_git(root, "rev-parse", "--git-dir").stdout
        except subprocess.CalledProcessError as exc:
            raise AdapterError("WORKTREE_MISMATCH", "path is not a linked worktree") from exc
        common = (root / common_raw.decode().strip()).resolve()
        git_dir = (root / git_dir_raw.decode().strip()).resolve()
        dot_git = root / ".git"
        if (
            inside != b"true"
            or not common_raw.strip()
            or not dot_git.is_file()
            or git_dir == common
            or git_dir.parent.name != "worktrees"
            or git_dir.parent.parent != common
        ):
            raise AdapterError("WORKTREE_MISMATCH", "path is not a linked worktree")
        remote = _run_git(
            root, "config", "--local", "--get", "remote.origin.url"
        ).stdout.decode().strip()
        if remote != expected_remote:
            raise AdapterError("REPOSITORY_MISMATCH", "canonical remote mismatch")
        branch_ref = _run_git(root, "symbolic-ref", "-q", "HEAD").stdout.decode().strip()
        branch = branch_ref.removeprefix("refs/heads/")
        if branch != request.branch:
            raise AdapterError("BRANCH_MISMATCH", "worktree branch mismatch")
        head = _run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        if head != request.expected_head_sha:
            raise AdapterError("HEAD_MISMATCH", "worktree HEAD mismatch")
        if require_clean and not self.is_clean(root):
            raise AdapterError("WORKTREE_MISMATCH", "worktree is not clean")
        self.verify_repository_types(root)
        return root

    @staticmethod
    def is_clean(root: Path) -> bool:
        _run_git(root, "update-index", "-q", "--refresh", check=False)
        tracked = _run_git(root, "diff-index", "--quiet", "HEAD", "--", check=False)
        untracked = _run_git(
            root, "ls-files", "--others", "--exclude-standard", "-z"
        ).stdout
        return tracked.returncode == 0 and not untracked

    def verify_repository_types(self, worktree: Path) -> None:
        entries = _run_git(worktree, "ls-files", "--stage", "-z").stdout
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            mode = entry.split(b" ", 1)[0]
            if mode == b"120000":
                raise AdapterError("MANIFEST_MISMATCH", "tracked symlinks are forbidden")
            if mode == b"160000":
                raise AdapterError("MANIFEST_MISMATCH", "submodules are forbidden")

    def tracked_readable_paths(
        self,
        worktree: Path,
        snapshot: str,
        manifest: AllowedPathManifest,
    ) -> frozenset[str]:
        """Resolve readable regular blobs from the immutable Git snapshot."""
        if snapshot != manifest.base_sha:
            raise AdapterError("MANIFEST_MISMATCH", "read snapshot mismatch")
        entries = _run_git(
            worktree, "ls-tree", "-rz", "--full-tree", "-r", snapshot
        ).stdout
        readable: set[str] = set()
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, _object_id = metadata.split(b" ", 2)
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise AdapterError(
                    "MANIFEST_MISMATCH", "unsafe object in readable snapshot"
                )
            try:
                path = safe_relative_path(raw_path.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise AdapterError(
                    "MANIFEST_MISMATCH", "non-UTF-8 tracked path is forbidden"
                ) from exc
            if manifest.permits_read(path):
                readable.add(path)
        return frozenset(readable)

    def changed_paths(self, worktree: Path, base_sha: str, head: str = "HEAD") -> list[str]:
        output = _run_git(
            worktree,
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACDMRTUXB",
            base_sha,
            head,
        ).stdout
        paths = [item.decode("utf-8") for item in output.split(b"\0") if item]
        return [safe_relative_path(path) for path in paths]

    def verify_paths(
        self, worktree: Path, paths: list[str], manifest: AllowedPathManifest
    ) -> None:
        for raw in paths:
            path = safe_relative_path(raw)
            if not manifest.permits(path):
                raise AdapterError("MANIFEST_MISMATCH", f"changed path forbidden: {path}")
            current = worktree
            for component in PurePosixPath(path).parts:
                current = current / component
                if current.is_symlink():
                    raise AdapterError("MANIFEST_MISMATCH", f"symlink forbidden: {path}")
        submodules = _run_git(
            worktree, "ls-files", "--stage", check=False
        ).stdout.decode().splitlines()
        if any(line.startswith("160000 ") for line in submodules):
            raise AdapterError("MANIFEST_MISMATCH", "submodules are forbidden")

    def verify_file_types(
        self, worktree: Path, paths: list[str], *, allow_missing: bool = True
    ) -> None:
        for raw in paths:
            path = worktree / safe_relative_path(raw)
            if not path.exists():
                if allow_missing:
                    continue
                raise AdapterError("MANIFEST_MISMATCH", f"missing path: {raw}")
            stat = path.lstat()
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise AdapterError("MANIFEST_MISMATCH", f"unsafe file type: {raw}")
            if path.is_file() and stat.st_nlink != 1:
                raise AdapterError("MANIFEST_MISMATCH", f"hard link forbidden: {raw}")

    def manifest_from_artifact(self, raw: bytes) -> AllowedPathManifest:
        return AllowedPathManifest(json.loads(raw))

    # -- review-orchestration snapshot observation ---------------------------
    @staticmethod
    def _verify_review_baseline(root: Path, starting_sha: str, head: str) -> str:
        """Re-prove that the exact baseline commit exists beneath ``head``."""
        try:
            baseline = (
                _run_git(root, "rev-parse", "--verify", f"{starting_sha}^{{commit}}")
                .stdout.decode()
                .strip()
            )
        except subprocess.CalledProcessError as exc:
            raise AdapterError("HEAD_MISMATCH", "starting baseline commit does not exist") from exc
        if baseline != starting_sha:
            raise AdapterError("HEAD_MISMATCH", "starting baseline is not an exact commit id")
        if _run_git(
            root, "merge-base", "--is-ancestor", baseline, head, check=False
        ).returncode:
            raise AdapterError("HEAD_MISMATCH", "baseline is not an ancestor of branch HEAD")
        return baseline

    def observe_review_baseline(
        self,
        worktree: str | Path,
        *,
        repository_id: str,
        branch: str,
        starting_sha: str,
        allowed_roots: frozenset[Path] = frozenset(),
        require_allowlisted_remote: bool = True,
    ) -> dict:
        """Observe a clean attached branch HEAD as the server-side baseline."""
        root = self.canonical_worktree_root(worktree, allowed_roots)
        branch_ref = _run_git(root, "symbolic-ref", "-q", "HEAD").stdout.decode().strip()
        observed_branch = branch_ref.removeprefix("refs/heads/")
        if observed_branch != branch:
            raise AdapterError("BRANCH_MISMATCH", "worktree branch mismatch")
        remote = (
            _run_git(root, "config", "--local", "--get", "remote.origin.url")
            .stdout.decode()
            .strip()
        )
        expected_remote = self._allowlist.get(repository_id)
        if require_allowlisted_remote:
            if expected_remote is None:
                raise AdapterError("REPOSITORY_MISMATCH", "repository is not allowlisted")
            if remote != expected_remote:
                raise AdapterError("REPOSITORY_MISMATCH", "canonical remote mismatch")
        status = _run_git(
            root,
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ).stdout
        if status:
            raise AdapterError("WORKTREE_MISMATCH", "job creation requires a clean worktree")
        head = _run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        branch_head = _run_git(root, "rev-parse", f"refs/heads/{branch}").stdout.decode().strip()
        if head != branch_head:
            raise AdapterError("HEAD_MISMATCH", "HEAD is not the current branch tip")
        baseline = self._verify_review_baseline(root, starting_sha, head)
        evidence = {
            "source": "server_verified_hermes_baseline_ancestor",
            "repository_id": repository_id,
            "canonical_remote": remote,
            "branch": observed_branch,
            "starting_sha": baseline,
            "current_head": head,
            "worktree_clean": True,
        }
        return {
            **evidence,
            "evidence_sha256": hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }

    @staticmethod
    def _read_regular_blob_state(root: Path, relpath: str) -> tuple[bytes, int]:
        """Read one regular file and its mode through no-follow descriptors."""
        parts = PurePosixPath(relpath).parts
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            file_fd = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            try:
                info = os.fstat(file_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise AdapterError("MANIFEST_MISMATCH", f"unsafe file type: {relpath}")
                chunks = []
                while True:
                    chunk = os.read(file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks), stat.S_IMODE(info.st_mode)
            finally:
                os.close(file_fd)
        except OSError as exc:
            raise AdapterError("MANIFEST_MISMATCH", f"unsafe file path: {relpath}") from exc
        finally:
            os.close(descriptor)

    @classmethod
    def _read_regular_blob(cls, root: Path, relpath: str) -> bytes:
        """Read one regular file through no-follow directory descriptors."""
        return cls._read_regular_blob_state(root, relpath)[0]

    @staticmethod
    def canonical_worktree_root(
        worktree: str | Path, allowed_roots: frozenset[Path] = frozenset()
    ) -> Path:
        """Canonicalize a worktree path and constrain it to trusted roots.

        Rejects NUL, traversal, non-absolute, non-canonical (symlink) aliases,
        and paths outside the configured allowed repository roots.
        """
        raw = os.fspath(worktree)
        if not raw or "\x00" in raw:
            raise AdapterError("WORKTREE_MISMATCH", "worktree path is empty or NUL")
        root = Path(raw)
        if not root.is_absolute():
            raise AdapterError("WORKTREE_MISMATCH", "worktree path must be absolute")
        try:
            real = root.resolve(strict=True)
        except OSError as exc:
            raise AdapterError("WORKTREE_MISMATCH", "worktree does not exist") from exc
        if real != root or root.is_symlink():
            raise AdapterError("WORKTREE_MISMATCH", "worktree path is not canonical")
        if allowed_roots:
            resolved_roots = frozenset(
                candidate.resolve(strict=True) for candidate in allowed_roots
            )
            if not any(
                real == root_resolved or root_resolved in real.parents
                for root_resolved in resolved_roots
            ):
                raise AdapterError(
                    "WORKTREE_MISMATCH", "worktree is outside allowed repository roots"
                )
        return real

    def observe_review_snapshot(
        self,
        worktree: str | Path,
        *,
        repository_id: str,
        branch: str,
        starting_sha: str,
        allowed_paths: list[str],
        allowed_roots: frozenset[Path] = frozenset(),
    ) -> dict:
        """Server-observed, zero-write snapshot of the review worktree.

        Independently reads the real worktree (remote, branch, HEAD, changed
        paths and their content) rather than trusting caller-supplied strings.
        Review and validation consume a committed ``HEAD`` tree, so staged,
        unstaged, and untracked content is rejected before a snapshot can be
        issued.  This keeps the reviewed bytes identical to ``git archive
        HEAD`` used by the Docker validation boundary.
        The returned ``head``/``diff_hash``/``allowed_paths`` are the only
        snapshot values bound into challenges and receipts.
        """
        root = self.canonical_worktree_root(worktree, allowed_roots)
        expected_remote = self._allowlist.get(repository_id)
        if expected_remote is None:
            raise AdapterError("REPOSITORY_MISMATCH", "repository is not allowlisted")
        remote = (
            _run_git(root, "config", "--local", "--get", "remote.origin.url")
            .stdout.decode()
            .strip()
        )
        if remote != expected_remote:
            raise AdapterError("REPOSITORY_MISMATCH", "canonical remote mismatch")
        branch_ref = _run_git(root, "symbolic-ref", "-q", "HEAD").stdout.decode().strip()
        if branch_ref.removeprefix("refs/heads/") != branch:
            raise AdapterError("BRANCH_MISMATCH", "worktree branch mismatch")
        head = _run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        self._verify_review_baseline(root, starting_sha, head)
        status = _run_git(
            root,
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ).stdout
        if status:
            raise AdapterError(
                "WORKTREE_MISMATCH",
                "review and validation require a clean committed HEAD",
            )
        tracked = _run_git(
            root,
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACDMRTUXB",
            starting_sha,
            head,
        ).stdout
        changed = sorted(
            {
                safe_relative_path(item.decode("utf-8"))
                for item in tracked.split(b"\0")
                if item
            }
        )
        allowed_matched = [
            path
            for path in changed
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in allowed_paths)
        ]
        forbidden = [path for path in changed if path not in allowed_matched]
        if forbidden:
            raise AdapterError(
                "MANIFEST_MISMATCH", f"changed path outside allowed set: {forbidden[0]}"
            )
        path_hashes = self._review_head_path_hashes(root, head, allowed_matched)
        diff_hash = self._review_diff_hash(path_hashes)
        final_head = _run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        self._verify_review_baseline(root, starting_sha, final_head)
        if (
            final_head != head
            or _run_git(
                root,
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ).stdout
        ):
            raise AdapterError(
                "WORKTREE_MISMATCH",
                "worktree changed while the committed snapshot was observed",
            )
        return {
            "head": head,
            "diff_hash": diff_hash,
            "allowed_paths": list(allowed_paths),
            "changed_paths": allowed_matched,
            "path_hashes": path_hashes,
            "snapshot_source": "committed_head",
            "worktree_clean": True,
        }

    @staticmethod
    def _review_head_path_hashes(
        root: Path, head: str, paths: list[str]
    ) -> dict[str, str]:
        """Hash type, mode, and content from the exact committed HEAD tree."""
        hashes: dict[str, str] = {}
        for path in paths:
            raw = _run_git(root, "ls-tree", "-z", head, "--", path).stdout
            entries = [entry for entry in raw.split(b"\0") if entry]
            if not entries:
                hashes[path] = "<deleted>"
                continue
            if len(entries) != 1:
                raise AdapterError("MANIFEST_MISMATCH", f"ambiguous Git object: {path}")
            metadata, raw_path = entries[0].split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            if raw_path.decode("utf-8") != path:
                raise AdapterError("MANIFEST_MISMATCH", f"Git path mismatch: {path}")
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise AdapterError("MANIFEST_MISMATCH", f"unsafe file type: {path}")
            content = _run_git(root, "cat-file", "blob", object_id.decode()).stdout
            state = {
                "type": "regular",
                "mode": int(mode[-3:], 8),
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            hashes[path] = hashlib.sha256(
                json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        return hashes

    @classmethod
    def _review_path_hashes(cls, root: Path, paths: list[str]) -> dict[str, str]:
        """Per-path digest binding regular-file content, type, and mode."""
        hashes: dict[str, str] = {}
        for path in paths:
            candidate = root / path
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                hashes[path] = "<deleted>"
                continue
            if not stat.S_ISREG(info.st_mode):
                raise AdapterError("MANIFEST_MISMATCH", f"unsafe file type: {path}")
            content, mode = cls._read_regular_blob_state(root, path)
            state = {
                "type": "regular",
                "mode": mode,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            hashes[path] = hashlib.sha256(
                json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        return hashes

    @classmethod
    def _review_diff_hash(cls, path_hashes: dict[str, str]) -> str:
        """Bind the challenge digest to a clean, committed HEAD tree."""
        material = {
            "snapshot_source": "committed_head",
            "worktree_clean": True,
            "paths": [[path, digest] for path, digest in sorted(path_hashes.items())],
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def materialize_tree(self, repo: Path, commit: str, destination: Path) -> None:
        """Materialize blobs with plumbing only; never invoke checkout machinery."""
        destination.mkdir(mode=0o700)
        entries = _run_git(
            repo, "ls-tree", "-rz", "--full-tree", "-r", commit
        ).stdout
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise AdapterError(
                    "MANIFEST_MISMATCH", "unsafe object in validation tree"
                )
            path = safe_relative_path(raw_path.decode("utf-8"))
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = _run_git(repo, "cat-file", "blob", object_id.decode()).stdout
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o700 if mode == b"100755" else 0o600,
            )
            try:
                os.write(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
