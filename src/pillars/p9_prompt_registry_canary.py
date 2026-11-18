"""Pillar 9: Vertex AI Prompt Registry, Canary A/B Routing & Drift Detection.

Satisfies:
- Invariant INV-13: Immutable versioned prompt registry with SHA-256 pinning,
  deterministic Canary traffic splitting, and PSI/Cosine drift auto-rollback.
- Requirement REQ-GCP-PROMPT-01: Manage Champion/Canary prompt lifecycles and
  halt/rollback Canary promotion when PSI >= 0.25 or semantic cosine shift >= 0.20.
"""

from __future__ import annotations

import hashlib
from typing import Any
from src.core.schemas import (
    CanaryRoutingDecision,
    DriftEvaluationReport,
    PromptVersionRecord,
)


class VertexPromptRegistryEngine:
    """Manages immutable prompt versions, Canary traffic routing, and drift rollback."""

    def __init__(self) -> None:
        self._registry: dict[str, list[PromptVersionRecord]] = {}
        self._seed_default_prompts()

    @staticmethod
    def _compute_checksum(template_text: str) -> str:
        return hashlib.sha256(template_text.encode("utf-8")).hexdigest()

    def _seed_default_prompts(self) -> None:
        prompt_id = "enterprise-procurement-supervisor"
        v1_text = (
            "You are the Vertex AI Procurement Supervisor. Verify Dataplex grounding (>=0.85), "
            "enforce Cloud DLP de-identification, and pause any spend > $5,000 USD for HITL."
        )
        v2_canary_text = (
            "You are the Vertex AI Procurement Supervisor v2. Prioritize Gemini 1.5 Flash for "
            "low-risk audits, enforce strict Cloud DLP tokenization, cite BigQuery tables, and "
            "gate disbursements > $5,000 USD with cryptographic OIDC approval."
        )
        self._registry[prompt_id] = [
            PromptVersionRecord(
                prompt_id=prompt_id,
                version="v1.0.0",
                template_text=v1_text,
                sha256_checksum=self._compute_checksum(v1_text),
                status="CHAMPION",
                traffic_weight=0.85,
            ),
            PromptVersionRecord(
                prompt_id=prompt_id,
                version="v1.1.0-canary",
                template_text=v2_canary_text,
                sha256_checksum=self._compute_checksum(v2_canary_text),
                status="CANARY",
                traffic_weight=0.15,
            ),
        ]

    def register_prompt_version(
        self,
        prompt_id: str,
        version: str,
        template_text: str,
        status: str = "CANARY",
        traffic_weight: float = 0.10,
    ) -> PromptVersionRecord:
        """Registers an immutable prompt template with SHA-256 checksum pinning."""
        record = PromptVersionRecord(
            prompt_id=prompt_id,
            version=version,
            template_text=template_text,
            sha256_checksum=self._compute_checksum(template_text),
            status="CHAMPION" if status == "CHAMPION" else "CANARY",
            traffic_weight=traffic_weight,
        )
        if prompt_id not in self._registry:
            self._registry[prompt_id] = []
        self._registry[prompt_id].append(record)
        return record

    def list_versions(self, prompt_id: str = "enterprise-procurement-supervisor") -> list[PromptVersionRecord]:
        """Returns all registered versions for a given prompt ID."""
        return self._registry.get(prompt_id, [])

    def route_canary_request(
        self,
        request_id: str,
        prompt_id: str = "enterprise-procurement-supervisor",
    ) -> CanaryRoutingDecision:
        """Deterministically routes request to Champion or Canary via hashed traffic bucket."""
        versions = self._registry.get(prompt_id, [])
        champion = next((v for v in versions if v.status == "CHAMPION"), None)
        canary = next((v for v in versions if v.status == "CANARY"), None)

        if not champion:
            raise KeyError(f"No active CHAMPION prompt registered for '{prompt_id}'.")

        # Deterministic bucket in [0.0, 1.0) derived from SHA-256 of request_id
        bucket_int = int(hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:8], 16)
        bucket_ratio = (bucket_int % 1000) / 1000.0

        if canary and bucket_ratio < canary.traffic_weight:
            selected = canary
            variant = "CANARY"
        else:
            selected = champion
            variant = "CHAMPION"

        return CanaryRoutingDecision(
            request_id=request_id,
            prompt_id=prompt_id,
            selected_version=selected.version,
            variant=variant,
            sha256_checksum=selected.sha256_checksum,
            shadow_comparison_enabled=canary is not None,
        )

    def evaluate_drift_and_auto_rollback(
        self,
        prompt_id: str = "enterprise-procurement-supervisor",
        observed_psi: float = 0.08,
        observed_cosine_shift: float = 0.04,
        psi_threshold: float = 0.25,
        cosine_threshold: float = 0.20,
    ) -> DriftEvaluationReport:
        """Evaluates distribution/semantic drift and automatically rolls back Canary if breached."""
        versions = self._registry.get(prompt_id, [])
        champion = next((v for v in versions if v.status == "CHAMPION"), None)
        canary = next((v for v in versions if v.status == "CANARY"), None)

        drift_detected = (observed_psi >= psi_threshold) or (observed_cosine_shift >= cosine_threshold)
        auto_rollback = False

        if drift_detected and canary is not None:
            canary.status = "ROLLED_BACK"
            canary.traffic_weight = 0.0
            if champion:
                champion.traffic_weight = 1.0
            auto_rollback = True

        return DriftEvaluationReport(
            prompt_id=prompt_id,
            psi_score=round(observed_psi, 4),
            cosine_shift=round(observed_cosine_shift, 4),
            drift_detected=drift_detected,
            auto_rollback_triggered=auto_rollback,
            active_champion_version=champion.version if champion else "unknown",
        )
