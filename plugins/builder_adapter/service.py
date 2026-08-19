"""Non-activated aiohttp UDS service factory."""

from __future__ import annotations

import os
import json
import stat
import asyncio
from pathlib import Path

from aiohttp import web

from .canonical import canonical_sha256, sha256_bytes
from .errors import AdapterError


def _strict_json(body: bytes) -> dict:
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise AdapterError("INVALID_REQUEST", "duplicate JSON key")
            value[key] = item
        return value

    value = json.loads(body, object_pairs_hook=object_pairs)
    if not isinstance(value, dict):
        raise AdapterError("INVALID_REQUEST", "JSON body must be an object")
    return value


class BuilderAdapterService:
    def __init__(
        self,
        adapter,
        authenticator,
        *,
        peer_resolver,
        orchestrator=None,
        review_routes_enabled: bool = True,
    ):
        self.adapter = adapter
        self.authenticator = authenticator
        self.peer_resolver = peer_resolver
        self.orchestrator = orchestrator
        self.review_routes_enabled = review_routes_enabled

    async def _principal(
        self, request: web.Request, body: bytes, *, canonical_payload: dict | None = None
    ) -> str:
        transport = request.transport
        sock = transport.get_extra_info("socket") if transport else None
        if sock is None:
            raise AdapterError("AUTHENTICATION_FAILED", "peer socket unavailable")
        uid, gid = self.peer_resolver(sock)
        return self.authenticator.verify(
            method=request.method,
            path=request.path_qs,
            timestamp=request.headers.get("X-Hermes-Timestamp", ""),
            nonce=request.headers.get("X-Hermes-Nonce", ""),
            request_sha256=(
                canonical_sha256(canonical_payload)
                if canonical_payload is not None
                else sha256_bytes(body)
            ),
            key_id=request.headers.get("X-Hermes-Key-Id", ""),
            signature=request.headers.get("X-Hermes-Signature", ""),
            peer_uid=uid,
            peer_gid=gid,
        )

    async def dispatch(self, request: web.Request) -> web.Response:
        body = await request.read()
        try:
            payload = _strict_json(body)
            principal = await self._principal(
                request, body, canonical_payload=payload
            )
            return web.json_response(self.adapter.dispatch(principal, payload))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            error = AdapterError("INVALID_REQUEST", "malformed JSON body")
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except AdapterError as error:
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except Exception:
            error = AdapterError("INTERNAL_ERROR", "request failed closed")
            return web.json_response({"errors": [error.as_dict()]}, status=500)

    async def status(self, request: web.Request) -> web.Response:
        try:
            principal = await self._principal(request, b"")
            result = self.adapter.get_status(
                principal,
                request.match_info["dispatch_id"],
                request.query.get("cycle_id", ""),
            )
            return web.json_response(result)
        except AdapterError as error:
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except Exception:
            error = AdapterError("INTERNAL_ERROR", "request failed closed")
            return web.json_response({"errors": [error.as_dict()]}, status=500)

    async def cancel(self, request: web.Request) -> web.Response:
        body = await request.read()
        try:
            payload = _strict_json(body)
            principal = await self._principal(
                request, body, canonical_payload=payload
            )
            result = self.adapter.cancel(
                principal,
                request.match_info["dispatch_id"],
                payload.get("cycle_id", ""),
                payload.get("reason_code", ""),
            )
            return web.json_response(result)
        except AdapterError as error:
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except (json.JSONDecodeError, UnicodeDecodeError):
            error = AdapterError("INVALID_REQUEST", "malformed JSON body")
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except Exception:
            error = AdapterError("INTERNAL_ERROR", "request failed closed")
            return web.json_response({"errors": [error.as_dict()]}, status=500)

    def _require_orchestrator(self):
        if self.orchestrator is None:
            raise AdapterError(
                "CAPABILITY_UNAVAILABLE", "review orchestrator is not configured"
            )
        return self.orchestrator

    async def _review_operation(
        self,
        request: web.Request,
        operation: str,
        *,
        job_id: str | None = None,
        reads_body: bool = True,
    ) -> web.Response:
        body = await request.read() if reads_body else b""
        try:
            payload = _strict_json(body) if reads_body else None
            principal = await self._principal(
                request, body, canonical_payload=payload if reads_body else None
            )
            orchestrator = self._require_orchestrator()
            if operation == "create":
                result = orchestrator.create(principal, payload)
            elif operation == "list":
                result = orchestrator.list(
                    principal,
                    phase=request.query.get("phase"),
                    status=request.query.get("status"),
                )
            elif operation == "get":
                result = orchestrator.get(principal, job_id)
            elif operation == "transition":
                result = orchestrator.transition(principal, job_id, payload)
            elif operation == "review":
                result = orchestrator.record_review(principal, job_id, payload)
            elif operation == "verification":
                result = orchestrator.record_verification(principal, job_id, payload)
            elif operation == "review_challenge":
                result = orchestrator.review_challenge(principal, job_id)
            elif operation == "verification_challenge":
                result = orchestrator.verification_challenge(principal, job_id)
            elif operation == "capsule":
                result = orchestrator.evidence_capsule(principal, job_id)
            else:  # pragma: no cover - internal dispatch
                raise AdapterError("INTERNAL_ERROR", "unknown review operation")
            return web.json_response(result)
        except AdapterError as error:
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except (json.JSONDecodeError, UnicodeDecodeError):
            error = AdapterError("INVALID_REQUEST", "malformed JSON body")
            return web.json_response({"errors": [error.as_dict()]}, status=400)
        except Exception:
            error = AdapterError("INTERNAL_ERROR", "request failed closed")
            return web.json_response({"errors": [error.as_dict()]}, status=500)

    async def _review_create(self, request: web.Request) -> web.Response:
        return await self._review_operation(request, "create")

    async def _review_list(self, request: web.Request) -> web.Response:
        return await self._review_operation(request, "list", reads_body=False)

    async def _review_get(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "get", job_id=request.match_info["job_id"], reads_body=False
        )

    async def _review_transition(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "transition", job_id=request.match_info["job_id"]
        )

    async def _review_record_review(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "review", job_id=request.match_info["job_id"]
        )

    async def _review_record_verification(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "verification", job_id=request.match_info["job_id"]
        )

    async def _review_get_review_challenge(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "review_challenge", job_id=request.match_info["job_id"], reads_body=False
        )

    async def _review_get_verification_challenge(
        self, request: web.Request
    ) -> web.Response:
        return await self._review_operation(
            request, "verification_challenge", job_id=request.match_info["job_id"], reads_body=False
        )

    async def _review_evidence_capsule(self, request: web.Request) -> web.Response:
        return await self._review_operation(
            request, "capsule", job_id=request.match_info["job_id"], reads_body=False
        )

    def application(self) -> web.Application:
        app = web.Application(client_max_size=1_000_000)
        app.router.add_post("/v1/dispatches", self.dispatch)
        app.router.add_get("/v1/dispatches/{dispatch_id}", self.status)
        app.router.add_post("/v1/dispatches/{dispatch_id}/cancel", self.cancel)

        if self.review_routes_enabled:
            app.router.add_post("/v1/review-jobs", self._review_create)
            app.router.add_get("/v1/review-jobs", self._review_list)
            app.router.add_get("/v1/review-jobs/{job_id}", self._review_get)
            app.router.add_post(
                "/v1/review-jobs/{job_id}/transition", self._review_transition
            )
            app.router.add_post(
                "/v1/review-jobs/{job_id}/review", self._review_record_review
            )
            app.router.add_post(
                "/v1/review-jobs/{job_id}/verification",
                self._review_record_verification,
            )
            app.router.add_get(
                "/v1/review-jobs/{job_id}/review-challenge",
                self._review_get_review_challenge,
            )
            app.router.add_get(
                "/v1/review-jobs/{job_id}/verification-challenge",
                self._review_get_verification_challenge,
            )
            app.router.add_get(
                "/v1/review-jobs/{job_id}/evidence-capsule",
                self._review_evidence_capsule,
            )

        async def health(_: web.Request) -> web.Response:
            return web.json_response(
                {
                    "capability_id": "hermes.builder_dispatch.v1",
                    "operational": True,
                    "process_id": os.getpid(),
                    "registered_cycles": len(self.adapter.cycle_registry),
                    "cycle_registry_sha256": canonical_sha256(
                        self.adapter.cycle_registry
                    ),
                }
            )

        app.router.add_get("/v1/health", health)
        return app


async def bind_unix_socket(
    app: web.Application, socket_path: str | Path
) -> tuple[web.AppRunner, web.UnixSite]:
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise AdapterError("AUTHORIZATION_FAILED", "socket parent cannot be symlink")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parent_stat = os.fstat(parent_fd)
    if parent_stat.st_uid != os.geteuid():  # windows-footgun: ok — Unix UDS service
        os.close(parent_fd)
        raise AdapterError("AUTHORIZATION_FAILED", "socket parent owner mismatch")
    if stat.S_IMODE(parent_stat.st_mode) != 0o700:
        os.fchmod(parent_fd, 0o700)
    os.close(parent_fd)
    if path.exists() or path.is_symlink():
        raise AdapterError("INTERNAL_ERROR", "socket path already exists")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.UnixSite(runner, str(path))
    await site.start()
    socket_stat = path.lstat()
    if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.geteuid():  # windows-footgun: ok — Unix UDS service
        await runner.cleanup()
        raise AdapterError("INTERNAL_ERROR", "bound UDS identity mismatch")
    os.chmod(path, 0o600)
    return runner, site


async def serve_until(
    app: web.Application, socket_path: str | Path, stop: asyncio.Event
) -> None:
    runner, _ = await bind_unix_socket(app, socket_path)
    try:
        await stop.wait()
    finally:
        await runner.cleanup()
        try:
            Path(socket_path).unlink()
        except FileNotFoundError:
            pass
