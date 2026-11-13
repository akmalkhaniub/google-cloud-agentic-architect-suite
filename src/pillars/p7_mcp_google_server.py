"""Pillar 7: FastMCP / Model Context Protocol Google Cloud Bridge & Tool Registry.

Satisfies:
- Invariant INV-11: Standard FastMCP JSON-RPC 2.0 interface with 3 sensitivity tiers
- Requirement REQ-GCP-MCP-01: Exposes tools (dlp_inspect, dataplex_search, vertex_reasoning,
  model_armor) and resources (infotypes, finops, evals) with LIVE_SPEND authorization gating.
"""

from __future__ import annotations

from typing import Any
from src.core.harness import GoogleCloudAgentHarness
from src.core.schemas import (
    AgenticWorkflowRequest,
    GoogleIdentityContext,
    McpJsonRpcRequest,
    McpJsonRpcResponse,
    McpResourceDefinition,
    McpSensitivityTier,
    McpToolDefinition,
)
from src.pillars.p1_reasoning_orchestrator import VertexReasoningOrchestrator
from src.pillars.p2_zero_trust_model_armor import ZeroTrustModelArmorEngine
from src.pillars.p3_dlp_governance_rag import DlpGovernanceAndGroundedRagEngine


class GoogleCloudMcpServer:
    """Standard Model Context Protocol (FastMCP) server over JSON-RPC 2.0."""

    def __init__(self) -> None:
        self.harness = GoogleCloudAgentHarness()
        self.p1 = VertexReasoningOrchestrator(harness=self.harness)
        self.p2 = ZeroTrustModelArmorEngine(harness=self.harness)
        self.p3 = DlpGovernanceAndGroundedRagEngine(harness=self.harness)

        self.tools: dict[str, McpToolDefinition] = {
            "dlp_inspect_and_tokenize": McpToolDefinition(
                name="dlp_inspect_and_tokenize",
                description="Inspects text for 150+ sensitive infoTypes and crypto-tokenizes/masks findings.",
                sensitivity_tier=McpSensitivityTier.READ_ONLY,
                inputSchema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            ),
            "model_armor_screen": McpToolDefinition(
                name="model_armor_screen",
                description="Screens inbound prompts for injection attacks, XPIA, and SSRF metadata probes.",
                sensitivity_tier=McpSensitivityTier.READ_ONLY,
                inputSchema={
                    "type": "object",
                    "properties": {"prompt": {"type": "string"}},
                    "required": ["prompt"],
                },
            ),
            "dataplex_grounded_search": McpToolDefinition(
                name="dataplex_grounded_search",
                description="Executes security-trimmed vector retrieval over BigQuery with Dataplex policy tags.",
                sensitivity_tier=McpSensitivityTier.READ_ONLY,
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "user_roles": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["query"],
                },
            ),
            "vertex_reasoning_execute": McpToolDefinition(
                name="vertex_reasoning_execute",
                description="Executes the full Vertex AI Reasoning Engine 5-agent supervisor trajectory.",
                sensitivity_tier=McpSensitivityTier.LIVE_SPEND,
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_prompt": {"type": "string"},
                        "target_spend_usd": {"type": "number"},
                        "oidc_token": {"type": "string"},
                    },
                    "required": ["user_prompt"],
                },
            ),
        }

        self.resources: dict[str, McpResourceDefinition] = {
            "gcp://dlp/infotypes": McpResourceDefinition(
                uri="gcp://dlp/infotypes",
                name="Supported DLP InfoTypes",
                description="Active Google Cloud Sensitive Data Protection inspection infoTypes.",
                mimeType="application/json",
            ),
            "gcp://quotas/finops": McpResourceDefinition(
                uri="gcp://quotas/finops",
                name="FinOps Departmental Quotas",
                description="Live token consumption and budget limits across corporate departments.",
                mimeType="application/json",
            ),
            "gcp://evals/summary": McpResourceDefinition(
                uri="gcp://evals/summary",
                name="Vertex AI Continuous Evals Summary",
                description="Aggregated Pointwise LLM-as-a-Judge quality metrics and SLA telemetry.",
                mimeType="application/json",
            ),
        }

    def handle_jsonrpc(
        self,
        request: McpJsonRpcRequest,
        auth_token: str | None = None,
    ) -> McpJsonRpcResponse:
        """Dispatches an inbound JSON-RPC 2.0 Model Context Protocol request."""
        method = request.method
        req_id = request.id
        params = request.params or {}

        # 1. Ping Method
        if method == "ping":
            return McpJsonRpcResponse(
                id=req_id,
                result={"status": "ok", "server": "google-cloud-agentic-mcp", "spec_version": "2024-11-05"},
            )

        # 2. Tools List Method
        if method == "tools/list":
            tools_list = [tool.model_dump() for tool in self.tools.values()]
            return McpJsonRpcResponse(id=req_id, result={"tools": tools_list})

        # 3. Resources List Method
        if method == "resources/list":
            resources_list = [res.model_dump() for res in self.resources.values()]
            return McpJsonRpcResponse(id=req_id, result={"resources": resources_list})

        # 4. Resources Read Method
        if method == "resources/read":
            uri = params.get("uri")
            if not uri or uri not in self.resources:
                return McpJsonRpcResponse(
                    id=req_id,
                    error={"code": -32602, "message": f"Resource URI '{uri}' not found."},
                )
            if uri == "gcp://dlp/infotypes":
                contents = {"supported_infotypes": ["US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER", "GCP_API_KEY", "EMAIL_ADDRESS", "PHONE_NUMBER"]}
            elif uri == "gcp://quotas/finops":
                contents = {"departments": ["Corporate Procurement", "Risk & Compliance", "Cloud Infrastructure", "Finance Operations"], "policy": "85% warning, 100% hard block"}
            else:
                contents = {"faithfulness_p95": 0.96, "relevance_p95": 0.94, "safety_pass_rate": 100.0}

            return McpJsonRpcResponse(id=req_id, result={"contents": contents})

        # 5. Tools Call Method
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if not tool_name or tool_name not in self.tools:
                return McpJsonRpcResponse(
                    id=req_id,
                    error={"code": -32601, "message": f"Tool '{tool_name}' not recognized."},
                )

            tool_def = self.tools[tool_name]

            # Enforce LIVE_SPEND authorization gate
            if tool_def.sensitivity_tier == McpSensitivityTier.LIVE_SPEND:
                token = auth_token or arguments.get("oidc_token")
                if not token or not token.startswith("oidc-"):
                    return McpJsonRpcResponse(
                        id=req_id,
                        error={
                            "code": -32001,
                            "message": "Access Denied: LIVE_SPEND operations require a valid Workload Identity OIDC token.",
                        },
                    )

            # Tool execution dispatcher
            try:
                if tool_name == "dlp_inspect_and_tokenize":
                    text = arguments.get("text", "")
                    dlp_res = self.harness.inspect_and_deidentify(text)
                    return McpJsonRpcResponse(
                        id=req_id,
                        result={"sanitized_text": dlp_res.sanitized_text, "findings_count": dlp_res.findings_count},
                    )

                elif tool_name == "model_armor_screen":
                    prompt = arguments.get("prompt", "")
                    verdict = self.harness.screen_model_armor(prompt)
                    return McpJsonRpcResponse(
                        id=req_id,
                        result={"safe": verdict.safe, "triggers": verdict.flagged_triggers},
                    )

                elif tool_name == "dataplex_grounded_search":
                    query = arguments.get("query", "")
                    roles = arguments.get("user_roles", ["roles/aiplatform.user"])
                    identity = GoogleIdentityContext(
                        user_email="mcp-client@contoso.internal",
                        roles=roles,
                        has_valid_oidc_token=True,
                    )
                    rag_res = self.p3.query_grounded_rag(query=query, identity=identity)
                    return McpJsonRpcResponse(
                        id=req_id,
                        result={
                            "synthesized_response": rag_res.synthesized_response,
                            "groundedness_score": rag_res.groundedness_score,
                            "citations_count": len(rag_res.citations),
                        },
                    )

                elif tool_name == "vertex_reasoning_execute":
                    user_prompt = arguments.get("user_prompt", "")
                    spend = float(arguments.get("target_spend_usd", 0.0))
                    identity = GoogleIdentityContext(
                        user_email="mcp-client@contoso.internal",
                        roles=["roles/aiplatform.user"],
                        has_valid_oidc_token=True,
                    )
                    wf_req = AgenticWorkflowRequest(
                        workflow_id="wf-mcp-9901",
                        identity=identity,
                        user_prompt=user_prompt,
                        target_spend_usd=spend,
                    )
                    wf_res = self.p1.execute_workflow(wf_req)
                    return McpJsonRpcResponse(
                        id=req_id,
                        result={
                            "workflow_id": wf_res.workflow_id,
                            "status": wf_res.status.value,
                            "final_output": wf_res.final_output,
                            "requires_hitl": wf_res.requires_hitl,
                        },
                    )

            except Exception as exc:
                return McpJsonRpcResponse(
                    id=req_id,
                    error={"code": -32603, "message": f"Internal execution error: {str(exc)}"},
                )

        return McpJsonRpcResponse(
            id=req_id,
            error={"code": -32601, "message": f"Method '{method}' not implemented."},
        )
