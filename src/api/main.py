"""FastAPI Cloud Run Service for Google Cloud Professional Agentic Architect Suite.

Enforces:
- Clean REST contracts & HTTP semantics (200 OK, 202 Accepted for HITL, 403 Forbidden for Model Armor)
- Asynchronous lifespan initializing Google Cloud Agent Harness and the 4 Pillar engines
- Interactive Google Cloud Solution Architect Workbench served at /
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.core.harness import GoogleCloudAgentHarness
from src.core.schemas import (
    AgenticWorkflowRequest,
    AgenticWorkflowResponse,
    DeidentificationMethod,
    DlpSanitizationResult,
    FinOpsQuotaMetrics,
    GoogleIdentityContext,
    GroundedSearchResult,
    HitlApprovalRequest,
    ModelArmorVerdict,
    WorkflowStatus,
)
from src.evals.runner import run_eight_gate_evaluation, run_four_gate_evaluation
from src.pillars.p1_reasoning_orchestrator import VertexReasoningOrchestrator
from src.pillars.p2_zero_trust_model_armor import ZeroTrustModelArmorEngine
from src.pillars.p3_dlp_governance_rag import DlpGovernanceAndGroundedRagEngine
from src.pillars.p4_resiliency_observability import ResiliencyAndObservabilityEngine
from src.pillars.p5_agent_memory_store import VertexAgentMemoryStore
from src.pillars.p6_bigquery_eval_studio import BigQueryEvaluationStudio
from src.pillars.p7_mcp_google_server import GoogleCloudMcpServer
from src.pillars.p8_a2a_resilient_circuit_breaker import A2AResilientCircuitBreaker

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize shared Google Cloud Agent Harness and the 8 Pillar engines."""
    harness = GoogleCloudAgentHarness()
    app.state.harness = harness
    app.state.pillar1 = VertexReasoningOrchestrator(harness=harness)
    app.state.pillar2 = ZeroTrustModelArmorEngine(harness=harness)
    app.state.pillar3 = DlpGovernanceAndGroundedRagEngine(harness=harness)
    app.state.pillar4 = ResiliencyAndObservabilityEngine(harness=harness)
    app.state.pillar5 = VertexAgentMemoryStore()
    app.state.pillar6 = BigQueryEvaluationStudio()
    app.state.pillar7 = GoogleCloudMcpServer()
    app.state.pillar8 = A2AResilientCircuitBreaker()
    yield


app = FastAPI(
    title="Google Cloud Professional Agentic Architect Suite",
    description="Enterprise reference architecture for Securing, Governing, and Orchestrating Agentic Workflows on GCP.",
    version="1.0.0",
    lifespan=lifespan,
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def root_workbench() -> FileResponse:
    """Serves the interactive Google Cloud Solution Architect Workbench."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/v1/health")
async def health_check() -> dict[str, Any]:
    """Cloud Run health & readiness probe."""
    harness: GoogleCloudAgentHarness = app.state.harness
    return {
        "status": "healthy",
        "service": "google-cloud-agentic-architect-suite",
        "project_id": harness.project_id,
        "pillars_online": [
            "Pillar 1: Vertex AI Reasoning Engine & Multi-Agent Graph",
            "Pillar 2: Zero-Trust Identity, VPC-SC & Model Armor Guardrails",
            "Pillar 3: Sensitive Data Protection (DLP) & Grounded Search",
            "Pillar 4: Cloud Trace Observability, Pub/Sub DLQ & FinOps",
            "Pillar 5: Multi-Tier Vertex Agent Memory & Memorystore Vector Distillation",
            "Pillar 6: BigQuery Continuous Evaluation & Vertex AI Studio",
            "Pillar 7: FastMCP / Model Context Protocol Google Cloud Server",
            "Pillar 8: Cloud Run Eventarc A2A & Resilient Circuit Breaker",
        ],
        "cloud_trace_spans_recorded": len(harness.trace_store),
        "dlq_messages_count": len(harness.dlq_store),
    }


# ============================================================================
# Pillar 1: Reasoning Engine & Multi-Agent Orchestrator
# ============================================================================

@app.post("/api/v1/pillar1/workflow/run", response_model=AgenticWorkflowResponse)
async def run_agentic_workflow(
    request: AgenticWorkflowRequest,
    response: Response,
) -> AgenticWorkflowResponse:
    """Executes multi-agent workflow with model cascade and Model Armor pre-screening."""
    p1: VertexReasoningOrchestrator = app.state.pillar1
    result = p1.execute_workflow(request)

    if result.status == WorkflowStatus.AWAITING_HUMAN_APPROVAL:
        response.status_code = status.HTTP_202_ACCEPTED
    elif result.status == WorkflowStatus.BLOCKED_BY_GUARDRAIL:
        response.status_code = status.HTTP_403_FORBIDDEN

    return result


@app.post(
    "/api/v1/pillar1/workflow/{workflow_id}/approve",
    response_model=AgenticWorkflowResponse,
)
async def approve_workflow_hitl(
    workflow_id: str,
    approval: HitlApprovalRequest,
) -> AgenticWorkflowResponse:
    """Resumes paused workflow upon receiving valid human reviewer approval."""
    p1: VertexReasoningOrchestrator = app.state.pillar1
    try:
        return p1.resume_after_hitl_approval(
            workflow_id=workflow_id,
            approver_email=approval.approver_email,
            oidc_sig=approval.oidc_signature,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


# ============================================================================
# Pillar 2: Zero-Trust & Model Armor
# ============================================================================

@app.post("/api/v1/pillar2/model-armor/screen", response_model=ModelArmorVerdict)
async def screen_prompt_model_armor(prompt: str, document: str | None = None) -> ModelArmorVerdict:
    """Evaluates arbitrary prompt and document payloads against Model Armor filters."""
    p2: ZeroTrustModelArmorEngine = app.state.pillar2
    return p2.evaluate_model_armor(prompt, document)


@app.post("/api/v1/pillar2/model-armor/adversarial-suite")
async def run_model_armor_adversarial_suite() -> dict[str, Any]:
    """Runs automated 6-scenario Model Armor test battery."""
    p2: ZeroTrustModelArmorEngine = app.state.pillar2
    return p2.run_adversarial_test_battery().model_dump()


# ============================================================================
# Pillar 3: Sensitive Data Protection (DLP) & Grounded Search
# ============================================================================

@app.post("/api/v1/pillar3/dlp/deidentify", response_model=DlpSanitizationResult)
async def deidentify_dlp(
    text: str,
    method: DeidentificationMethod = DeidentificationMethod.CRYPTO_TOKENIZATION,
) -> DlpSanitizationResult:
    """Inspects and de-identifies PII infoTypes via Cloud DLP."""
    p3: DlpGovernanceAndGroundedRagEngine = app.state.pillar3
    return p3.deidentify_text(text, method=method)


@app.post("/api/v1/pillar3/rag/query", response_model=GroundedSearchResult)
async def query_grounded_rag(
    query: str,
    identity: GoogleIdentityContext,
    use_cache: bool = True,
) -> GroundedSearchResult:
    """Executes security-trimmed Grounded RAG with Dataplex policy tags."""
    p3: DlpGovernanceAndGroundedRagEngine = app.state.pillar3
    return p3.query_grounded_rag(query, identity, use_semantic_cache=use_cache)


# ============================================================================
# Pillar 4: Observability, Pub/Sub & FinOps
# ============================================================================

@app.get("/api/v1/pillar4/finops/metrics", response_model=list[FinOpsQuotaMetrics])
async def get_finops_metrics() -> list[FinOpsQuotaMetrics]:
    """Retrieves token quotas and budget burn rates across all enterprise departments."""
    p4: ResiliencyAndObservabilityEngine = app.state.pillar4
    return p4.get_all_department_metrics()


@app.get("/api/v1/pillar4/telemetry/spans")
async def get_cloud_trace_spans() -> list[dict[str, Any]]:
    """Retrieves recent OpenTelemetry GenAI spans exported to Cloud Trace."""
    p4: ResiliencyAndObservabilityEngine = app.state.pillar4
    return [s.model_dump() for s in p4.get_recent_trace_spans(limit=25)]


# ============================================================================
# Cross-Cutting: 4-Gate & 8-Gate Automated Evaluation Suites
# ============================================================================

@app.post("/api/v1/evals/run")
async def trigger_four_gate_evals() -> dict[str, Any]:
    """Executes the foundational 4-Gate Evaluation Suite."""
    return run_four_gate_evaluation()


@app.post("/api/v1/evals/eight-gate/run")
async def trigger_eight_gate_evals() -> dict[str, Any]:
    """Executes the comprehensive 8-Gate Evaluation Suite."""
    return run_eight_gate_evaluation()


# ============================================================================
# Pillar 5: Multi-Tier Agent Memory & Memorystore Vector Distillation
# ============================================================================

@app.post("/api/v1/pillar5/memory/recall")
async def recall_agent_memories(
    tenant_id: str = "tenant-corp-01",
    query: str = "expedited server procurement",
    threshold: float = 0.82,
) -> dict[str, Any]:
    """Recalls episodic memories and distilled governance rules."""
    p5: VertexAgentMemoryStore = app.state.pillar5
    return p5.recall_memories(tenant_id=tenant_id, query=query, min_similarity_threshold=threshold).model_dump()


@app.post("/api/v1/pillar5/memory/distill")
async def distill_governance_rule(
    tenant_id: str = "tenant-corp-01",
    category: str = "Policy Rule",
    rule_text: str = "Mandatory sign-off required for orders exceeding $10k.",
    source_workflow_id: str = "wf-api-distill",
) -> dict[str, Any]:
    """Distills feedback into a persistent governance rule."""
    p5: VertexAgentMemoryStore = app.state.pillar5
    return p5.distill_rule_from_feedback(tenant_id, category, rule_text, source_workflow_id).model_dump()


# ============================================================================
# Pillar 6: BigQuery Continuous Evaluation & Vertex AI Studio
# ============================================================================

@app.post("/api/v1/pillar6/bigquery/query")
async def run_bigquery_analytics(query_name: str = "token_spend_by_department") -> dict[str, Any]:
    """Executes BigQuery SQL queries over continuous evaluation traces."""
    p6: BigQueryEvaluationStudio = app.state.pillar6
    return p6.run_bigquery_analytics_query(query_name).model_dump()


# ============================================================================
# Pillar 7: FastMCP / Model Context Protocol Google Cloud Server
# ============================================================================

@app.post("/api/v1/pillar7/mcp/jsonrpc")
async def handle_mcp_jsonrpc(
    request: dict[str, Any],
    auth_token: str | None = None,
) -> dict[str, Any]:
    """Handles JSON-RPC 2.0 FastMCP requests (tools/list, tools/call, resources/list)."""
    p7: GoogleCloudMcpServer = app.state.pillar7
    from src.core.schemas import McpJsonRpcRequest
    rpc_req = McpJsonRpcRequest(**request)
    return p7.handle_jsonrpc(rpc_req, auth_token=auth_token).model_dump()


# ============================================================================
# Pillar 8: Cloud Run Eventarc A2A & Resilient Circuit Breaker
# ============================================================================

@app.get("/api/v1/pillar8/circuit-breaker/status")
async def get_circuit_breaker_status() -> dict[str, Any]:
    """Retrieves operational status and fault metrics of the circuit breaker."""
    p8: A2AResilientCircuitBreaker = app.state.pillar8
    return p8.get_status().model_dump()


@app.post("/api/v1/pillar8/a2a/dispatch")
async def dispatch_a2a_agent_call(
    sender_agent: str = "SupervisorAgent",
    target_agent: str = "ComplianceAuditorAgent",
    intent: str = "CLEARANCE_CHECK",
    simulate_fault: int | None = None,
) -> dict[str, Any]:
    """Dispatches inter-agent communication through resilient circuit breaker."""
    p8: A2AResilientCircuitBreaker = app.state.pillar8
    return p8.execute_with_circuit_breaker(sender_agent, target_agent, intent, simulate_fault=simulate_fault)
