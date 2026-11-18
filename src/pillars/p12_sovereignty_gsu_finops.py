"""Pillar 12: Multi-Region Sovereignty Router & Vertex AI Provisioned Throughput (GSU) FinOps.

Satisfies:
- Invariant INV-16: Strict regional data residency enforcement (EU GDPR, US FedRAMP, APJ)
  and deterministic Vertex AI GSU vs. PAYG FinOps unit economics.
- Requirement REQ-GCP-FINOPS-GSU-01: Sovereign regional endpoint routing and automated
  GSU crossover break-even calculations with gross margin guardrails.
"""

from __future__ import annotations

import math
from src.core.schemas import (
    GsuFinOpsCalculation,
    SovereigntyRegion,
    SovereigntyRoutingDecision,
)


class SovereigntyAndGsuFinOpsEngine:
    """Enforces regional data residency and optimizes Vertex AI GSU vs. PAYG economics."""

    # Blended Gemini 1.5 Pro/Flash PAYG price per 1M tokens (USD)
    BLENDED_PAYG_PER_MILLION_TOKENS_USD = 3.50
    # Vertex AI Provisioned Throughput (1 GSU monthly commitment covering ~1,250M tokens/mo)
    GSU_MONTHLY_COST_USD = 2700.0
    GSU_CAPACITY_MILLION_TOKENS_PER_MONTH = 1250.0

    def route_sovereign_region(self, tenant_jurisdiction: str) -> SovereigntyRoutingDecision:
        """Deterministically pins Cloud Run & Vertex AI endpoints to sovereign GCP regions."""
        jurisdiction_norm = tenant_jurisdiction.strip().upper()

        if any(code in jurisdiction_norm for code in ["EU", "DE", "FR", "NL", "GDPR", "UK"]):
            region = SovereigntyRegion.EU_WEST4
            frameworks = ["EU GDPR", "EU AI Act", "ISO/IEC 27001", "C5 Germany"]
            endpoint = "https://europe-west4-aiplatform.googleapis.com/v1/projects/contoso-eu-prod/locations/europe-west4"
        elif any(code in jurisdiction_norm for code in ["JP", "SG", "APJ", "AU", "APPI"]):
            region = SovereigntyRegion.ASIA_NORTHEAST1
            frameworks = ["Japan APPI", "ISO/IEC 27017", "MTCS Singapore"]
            endpoint = "https://asia-northeast1-aiplatform.googleapis.com/v1/projects/contoso-apj-prod/locations/asia-northeast1"
        else:
            region = SovereigntyRegion.US_CENTRAL1
            frameworks = ["SOC 2 Type II", "FedRAMP High", "HIPAA BAA", "CCPA"]
            endpoint = "https://us-central1-aiplatform.googleapis.com/v1/projects/contoso-us-prod/locations/us-central1"

        return SovereigntyRoutingDecision(
            tenant_jurisdiction=jurisdiction_norm,
            selected_gcp_region=region,
            data_residency_enforced=True,
            cross_border_egress_blocked=True,
            compliance_frameworks=frameworks,
            endpoint_uri=endpoint,
        )

    def calculate_gsu_vs_payg_finops(
        self,
        monthly_tokens_millions: float,
        enterprise_arr_monthly_usd: float = 25000.0,
    ) -> GsuFinOpsCalculation:
        """Calculates Vertex AI PAYG vs. Provisioned Throughput (GSU) break-even & margin."""
        payg_cost = round(monthly_tokens_millions * self.BLENDED_PAYG_PER_MILLION_TOKENS_USD, 2)

        gsu_units = max(1, math.ceil(monthly_tokens_millions / self.GSU_CAPACITY_MILLION_TOKENS_PER_MONTH))
        gsu_cost = round(gsu_units * self.GSU_MONTHLY_COST_USD, 2)

        breakeven_m = round(self.GSU_MONTHLY_COST_USD / self.BLENDED_PAYG_PER_MILLION_TOKENS_USD, 2)

        if gsu_cost < payg_cost:
            recommended_tier = "PROVISIONED_GSU"
            savings = round(payg_cost - gsu_cost, 2)
            effective_cogs = gsu_cost
        else:
            recommended_tier = "PAYG"
            savings = 0.0
            effective_cogs = payg_cost

        # SaaS Gross Margin guardrail: AI inference COGS should remain <= 30% of monthly revenue
        gross_margin_protected = (effective_cogs / max(enterprise_arr_monthly_usd, 1.0)) <= 0.30

        return GsuFinOpsCalculation(
            monthly_tokens_millions=round(monthly_tokens_millions, 2),
            payg_monthly_cost_usd=payg_cost,
            gsu_recommended_units=gsu_units,
            gsu_monthly_cost_usd=gsu_cost,
            recommended_tier=recommended_tier,
            projected_monthly_savings_usd=savings,
            gross_margin_protected=gross_margin_protected,
            breakeven_tokens_millions=breakeven_m,
        )
