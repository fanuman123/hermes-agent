"""Narrow internal dispatch over the trusted review producers.

``build_runtime`` constructs one :class:`~.review_receipts.ReceiptAuthority`
shared by the orchestrator, the review runner, and the validation attestor,
then retains the concrete runner/attestor handles behind this object.  The
HTTP surface never receives this object or the authority: ordinary callers can
only submit already-minted receipts through the orchestrator's public
operations.  This dispatch is the sole production path that mints, and it
returns only signed receipts and the resulting records -- never the secrets,
the authority object, or its mint methods.
"""

from __future__ import annotations

from .review_orchestrator import (
    ACTOR_CODEX,
    ACTOR_HERMES,
    CHALLENGE_KIND_REVIEW,
    CHALLENGE_KIND_VERIFICATION,
    ReviewOrchestrator,
)
from .review_receipts import ReviewRunner, ValidationAttestor


class ReviewRuntime:
    """Trusted, non-HTTP internal dispatch for minting review/validation receipts."""

    def __init__(
        self,
        orchestrator: ReviewOrchestrator,
        runner: ReviewRunner,
        attestor: ValidationAttestor,
    ):
        self._orchestrator = orchestrator
        self._runner = runner
        self._attestor = attestor

    def run_review(self, *, job_id: str, prompt: str) -> dict:
        """Mint a review runner receipt for the active challenge and record it.

        The concrete Codex backend launches the review, the runner computes the
        modified-file proof itself, and the resulting signed receipt is
        submitted to the orchestrator as the codex_mcp actor.
        """
        challenge = self._orchestrator.active_challenge(job_id, CHALLENGE_KIND_REVIEW)
        receipt = self._runner.run(challenge=challenge, prompt=prompt)
        record = self._orchestrator.record_review(
            ACTOR_CODEX, job_id, {"receipt": receipt}
        )
        return {"receipt": receipt, "record": record}

    def run_validation(
        self,
        *,
        job_id: str,
        profile_id: str,
        focused_test: dict,
        full_test: dict,
    ) -> dict:
        """Mint a validation receipt for the active challenge and record it.

        The attestor runs the isolated validation path and mints only after
        recomputing the canonical evidence; the receipt is submitted to the
        orchestrator as the hermes actor together with Hermes' own focused and
        full test results.
        """
        challenge = self._orchestrator.active_challenge(
            job_id, CHALLENGE_KIND_VERIFICATION
        )
        receipt = self._attestor.run(challenge=challenge, profile_id=profile_id)
        record = self._orchestrator.record_verification(
            ACTOR_HERMES,
            job_id,
            {
                "receipt": receipt,
                "focused_test": focused_test,
                "full_test": full_test,
            },
        )
        return {"receipt": receipt, "record": record}
