"""Pillar 4: Cloud Trace Observability, Pub/Sub Resiliency & FinOps Quotas (`REQ-GCP-RES-01`, `REQ-GCP-OBS-01`).

Implements:
- Distributed OpenTelemetry tracing to Google Cloud Trace with gen_ai.* attributes (INV-08)
- Cloud Pub/Sub retry policies and Dead-Letter Queue (DLQ) recovery (INV-07)
- Departmental FinOps token quotas, budget burn alerts, and cost attribution
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from src.core.harness import GoogleCloudAgentHarness
from src.core.schemas import (
    CloudTraceSpan,
    FinOpsQuotaMetrics,
    PubSubMessageEnvelope,
)


class ResiliencyAndObservabilityEngine:
    """Enterprise engine coordinating Google Cloud Trace, Pub/Sub DLQ, and FinOps budgeting."""

    def __init__(self, harness: GoogleCloudAgentHarness | None = None) -> None:
        self.harness = harness or GoogleCloudAgentHarness()
        self._department_budgets: dict[str, dict[str, Any]] = {
            "Corporate Procurement": {"budget_usd": 1500.0, "tpm_limit": 150000},
            "Legal & Compliance": {"budget_usd": 2500.0, "tpm_limit": 200000},
            "SRE & Infrastructure": {"budget_usd": 3000.0, "tpm_limit": 300000},
            "Finance & Treasury": {"budget_usd": 1800.0, "tpm_limit": 180000},
        }
        self._seed_spans()

    def _seed_spans(self) -> None:
        """Seeds realistic historical spans for multi-department FinOps attribution."""
        sample_spans = [
            ("Corporate Procurement", "gemini-1.5-flash-002", 1250, 280, 0.00418, 48.0, "Supervisor.Route"),
            ("Corporate Procurement", "gemini-1.5-pro-002", 3400, 890, 0.01214, 142.0, "Analysis.ComplexContract"),
            ("Legal & Compliance", "gemini-1.5-pro-002", 5200, 1450, 0.01910, 210.0, "Compliance.DeepAudit"),
            ("Legal & Compliance", "gemini-1.5-flash-002", 900, 210, 0.00306, 32.0, "DLP.Sanitize"),
            ("SRE & Infrastructure", "gemini-1.5-flash-002", 800, 180, 0.00268, 28.0, "PubSub.DLQMonitor"),
            ("Finance & Treasury", "gemini-1.5-pro-002", 4100, 920, 0.01372, 165.0, "FinOps.BudgetProjection"),
        ]
        for dept, model, p_tok, c_tok, cost, latency, name in sample_spans:
            span = CloudTraceSpan(
                span_id=f"span-seed-{uuid.uuid4().hex[:6]}",
                trace_id=f"trace-seed-{uuid.uuid4().hex[:12]}",
                name=name,
                department=dept,
                model=model,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                cost_usd=cost,
                latency_ms=latency,
                status_code="OK",
            )
            self.harness.trace_store.append(span)

    def dispatch_pubsub_event(
        self,
        topic: str,
        payload: dict[str, Any],
        simulate_outage: bool = False,
    ) -> PubSubMessageEnvelope:
        """Dispatches an asynchronous event message via Cloud Pub/Sub with DLQ handling (`REQ-GCP-RES-01`)."""
        return self.harness.publish_eventarc_message(topic, payload, simulate_503=simulate_outage)

    def get_department_finops_metrics(self, department: str) -> FinOpsQuotaMetrics:
        """Calculates token consumption, spend, and budget burn rate per department (`REQ-GCP-OBS-01`)."""
        config = self._department_budgets.get(department, {"budget_usd": 1000.0, "tpm_limit": 100000})
        dept_spans = [s for s in self.harness.trace_store if s.department == department]

        total_cost = sum(s.cost_usd for s in dept_spans)
        total_tokens = sum(s.prompt_tokens + s.completion_tokens for s in dept_spans)
        budget = config["budget_usd"]
        burn_pct = round((total_cost / budget) * 100.0, 2)

        return FinOpsQuotaMetrics(
            department=department,
            allocated_budget_usd=budget,
            current_spend_usd=round(total_cost, 4),
            tokens_consumed=total_tokens,
            tpm_limit=config["tpm_limit"],
            budget_exceeded=total_cost > budget,
            cost_burn_percent=burn_pct,
        )

    def get_all_department_metrics(self) -> list[FinOpsQuotaMetrics]:
        """Returns FinOps metrics across all enterprise departments."""
        return [self.get_department_finops_metrics(dept) for dept in self._department_budgets]

    def get_recent_trace_spans(self, limit: int = 25) -> list[CloudTraceSpan]:
        """Returns the most recent OpenTelemetry GenAI spans exported to Google Cloud Trace."""
        return list(reversed(self.harness.trace_store[-limit:]))


# Global singleton instance
resiliency_observability_engine = ResiliencyAndObservabilityEngine()
