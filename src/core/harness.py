"""Runtime Agent Harness for Google Cloud Professional Agentic Architect Suite.

Enforces:
- Invariant INV-01: Keyless Workload Identity validation
- Invariant INV-02: Google Cloud Model Armor prompt injection shields
- Invariant INV-03: Cloud Sensitive Data Protection (DLP) infoType inspection & masking
- Invariant INV-05: Customer-Managed Encryption Key (CMEK) signing for spend
- Invariant INV-07: Pub/Sub exponential backoff retry and Dead-Letter Queue (DLQ)
- Invariant INV-08: OpenTelemetry GenAI semantic conventions exported to Cloud Trace
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any

from src.core.schemas import (
    CloudTraceSpan,
    CmekEnvelope,
    DeidentificationMethod,
    DlpFinding,
    DlpSanitizationResult,
    GoogleIdentityContext,
    InfoType,
    ModelArmorVerdict,
    PubSubMessageEnvelope,
    VpcServiceControlsCheck,
    utc_now_iso,
)


class SecurityPolicyViolationError(Exception):
    """Raised when an inbound request violates VPC-SC or Model Armor policies."""
    pass


class LiveSpendBlockedError(Exception):
    """Raised when spend > $5,000 USD is attempted without valid cryptographic approval."""
    pass


class GoogleCloudAgentHarness:
    """Enterprise runtime harness orchestrating Google Cloud security, DLP, and telemetry."""

    def __init__(self, project_id: str = "contoso-ai-prod-01") -> None:
        self.project_id = project_id
        self.trace_store: list[CloudTraceSpan] = []
        self.dlq_store: list[PubSubMessageEnvelope] = []
        self.audit_log: list[dict[str, Any]] = []

    # ========================================================================
    # 1. Workload Identity & VPC Service Controls Validation (INV-01, INV-06)
    # ========================================================================
    def validate_workload_identity(self, identity: GoogleIdentityContext) -> VpcServiceControlsCheck:
        """Validates keyless Workload Identity Federation OIDC token and VPC-SC perimeter."""
        if not identity.has_valid_oidc_token:
            raise SecurityPolicyViolationError("Authentication Failed: Missing or invalid short-lived OIDC federated token.")

        # Simulate VPC-SC perimeter policy check
        perimeter_ok = "sp_vertex_ai_core" in identity.vpc_sc_perimeter_id
        return VpcServiceControlsCheck(
            perimeter_name=identity.vpc_sc_perimeter_id,
            source_ip_allowed=True,
            egress_rule_matched=perimeter_ok,
            access_granted=perimeter_ok,
            denial_reason=None if perimeter_ok else "VPC Service Controls: Request origin outside authorized access policy.",
        )

    # ========================================================================
    # 2. Google Cloud Sensitive Data Protection (DLP) (INV-03)
    # ========================================================================
    def inspect_and_deidentify(
        self,
        text: str,
        method: DeidentificationMethod = DeidentificationMethod.CRYPTO_TOKENIZATION,
    ) -> DlpSanitizationResult:
        """Inspects text for PII infoTypes and de-identifies before LLM context ingestion."""
        findings: list[DlpFinding] = []
        sanitized = text

        patterns: list[tuple[InfoType, str]] = [
            (InfoType.EMAIL_ADDRESS, r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
            (InfoType.PHONE_NUMBER, r"\b(?:\+?1[-.]?)?\(?[2-9]\d{2}\)?[-.]?\d{3}[-.]?\d{4}\b"),
            (InfoType.US_SOCIAL_SECURITY_NUMBER, r"\b\d{3}-\d{2}-\d{4}\b"),
            (InfoType.CREDIT_CARD_NUMBER, r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
            (InfoType.GCP_API_KEY, r"\bAIza[0-9A-Za-z-_]{30,40}\b"),
            (InfoType.PROJECT_CODENAME, r"\bProject\s+(?:Titan|Apollo|Omega|Valhalla)\b"),
        ]

        for info_type, regex in patterns:
            matches = list(re.finditer(regex, sanitized, flags=re.IGNORECASE))
            for match in reversed(matches):
                val = match.group(0)
                snippet_hash = hashlib.sha256(val.encode()).hexdigest()[:8]

                if method == DeidentificationMethod.CRYPTO_TOKENIZATION:
                    token = f"[TOK_{info_type.value}_{snippet_hash}]"
                elif method == DeidentificationMethod.REDACTION:
                    token = f"[REDACTED_{info_type.value}]"
                else:
                    token = f"***{info_type.value}***"

                findings.append(
                    DlpFinding(
                        info_type=info_type,
                        likelihood="VERY_LIKELY",
                        original_snippet_hash=snippet_hash,
                        replacement_token=token,
                    )
                )
                start, end = match.span()
                sanitized = sanitized[:start] + token + sanitized[end:]

        return DlpSanitizationResult(
            original_length=len(text),
            sanitized_text=sanitized,
            findings_count=len(findings),
            findings=findings,
            deidentification_method=method,
        )

    # ========================================================================
    # 3. Google Cloud Model Armor & Prompt Shield Screening (INV-02)
    # ========================================================================
    def screen_model_armor(self, prompt: str, document_text: str | None = None) -> ModelArmorVerdict:
        """Evaluates inbound prompts & external documents against Model Armor filters."""
        combined = f"{prompt} {document_text or ''}".lower()
        flagged: list[str] = []
        user_attack = False
        doc_attack = False
        leakage = False

        # UPIA: Direct User Prompt Injections
        if any(p in combined for p in ["ignore all previous", "override system", "disregard instructions", "developer mode"]):
            user_attack = True
            flagged.append("MODEL_ARMOR_UPIA_DIRECT_JAILBREAK")

        # XPIA: Cross-Prompt Indirect Injections inside documents
        if document_text and any(p in document_text.lower() for p in ["[system action:", "override approval", "auto-approve funds"]):
            doc_attack = True
            flagged.append("MODEL_ARMOR_XPIA_INDIRECT_DOCUMENT_INJECTION")

        # System Prompt Extraction
        if any(p in combined for p in ["system prompt", "foundational instructions", "safety rules", "xml guardrails"]):
            leakage = True
            flagged.append("MODEL_ARMOR_SYSTEM_PROMPT_LEAKAGE")

        is_safe = not (user_attack or doc_attack or leakage)

        return ModelArmorVerdict(
            safe=is_safe,
            user_prompt_attack_detected=user_attack,
            document_attack_detected=doc_attack,
            system_prompt_leakage_detected=leakage,
            flagged_triggers=flagged,
            confidence_score=0.99 if not is_safe else 0.98,
            latency_ms=4.2,
        )

    # ========================================================================
    # 4. Cloud KMS CMEK Signing & Verification (INV-05)
    # ========================================================================
    def generate_cmek_envelope(self, payload_str: str) -> CmekEnvelope:
        """Simulates Cloud KMS Customer-Managed Encryption Key envelope signing."""
        h = hashlib.sha256(payload_str.encode()).hexdigest()
        key_id = f"projects/{self.project_id}/locations/us-central1/keyRings/kr-agent-governance/cryptoKeys/key-agent-payloads"
        return CmekEnvelope(
            key_id=key_id,
            ciphertext_hash=h,
            algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
            encrypted_at=utc_now_iso(),
        )

    # ========================================================================
    # 5. Cloud Pub/Sub Retry & Dead-Letter Queue (DLQ) (INV-07)
    # ========================================================================
    def publish_eventarc_message(
        self,
        topic: str,
        payload: dict[str, Any],
        simulate_503: bool = False,
    ) -> PubSubMessageEnvelope:
        """Simulates Cloud Pub/Sub delivery with exponential retry and DLQ routing."""
        msg_id = f"msg-{uuid.uuid4().hex[:8]}"

        if simulate_503:
            # First 2 attempts fail with HTTP 503; attempt 3 succeeds, or routes to DLQ if unrecoverable
            env = PubSubMessageEnvelope(
                message_id=msg_id,
                topic=f"{topic}-dlq",
                delivery_attempt=3,
                status="DEAD_LETTERED",
                dead_letter_reason="HTTP 503: Vertex AI downstream ERP unavailable after 3 exponential backoff retries.",
                payload=payload,
                timestamp=utc_now_iso(),
            )
            self.dlq_store.append(env)
            return env

        env = PubSubMessageEnvelope(
            message_id=msg_id,
            topic=topic,
            delivery_attempt=1,
            status="DELIVERED",
            dead_letter_reason=None,
            payload=payload,
            timestamp=utc_now_iso(),
        )
        return env

    # ========================================================================
    # 6. OpenTelemetry to Cloud Trace Recording (INV-08)
    # ========================================================================
    def record_trace_span(
        self,
        name: str,
        department: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        status_code: str = "OK",
    ) -> CloudTraceSpan:
        """Emits an OpenTelemetry GenAI span into the Cloud Trace store."""
        cost = round((prompt_tokens * 0.000002) + (completion_tokens * 0.000006), 6)
        span = CloudTraceSpan(
            span_id=f"span-{uuid.uuid4().hex[:8]}",
            trace_id=f"trace-{uuid.uuid4().hex[:16]}",
            name=name,
            department=department,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            latency_ms=latency_ms,
            status_code=status_code,
            timestamp=utc_now_iso(),
        )
        self.trace_store.append(span)
        return span
