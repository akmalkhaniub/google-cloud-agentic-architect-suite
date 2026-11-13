"""Core Pydantic v2 schemas and data contracts for Google Cloud Professional Agentic Architect Suite.

Enforces:
- Invariant INV-01: Keyless Workload Identity Federation & Google Cloud context
- Invariant INV-02: Google Cloud Model Armor prompt injection shields
- Invariant INV-03: Cloud Sensitive Data Protection (DLP) infoTypes & de-identification
- Invariant INV-04: Groundedness & citation attribution contracts
- Invariant INV-05: Human-in-the-Loop approval checkpoints for spend > $5,000 USD
- Invariant INV-07: Cloud Pub/Sub retry and Dead-Letter Queue envelopes
- Invariant INV-08: OpenTelemetry GenAI semantic conventions for Google Cloud Trace
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Returns ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# 1. Enums & Common Domain Models
# ============================================================================

class ModelTier(str, Enum):
    """Gemini dynamic model tiers on Vertex AI (`REQ-GCP-ARCH-01`)."""
    GEMINI_1_5_FLASH = "gemini-1.5-flash-002"
    GEMINI_1_5_PRO = "gemini-1.5-pro-002"


class WorkflowStatus(str, Enum):
    """Lifecycle state machine for enterprise agentic workflows."""
    COMPLETED = "completed"
    AWAITING_HUMAN_APPROVAL = "awaiting_human_approval"
    BLOCKED_BY_GUARDRAIL = "blocked_by_guardrail"
    RETRYING = "retrying"
    DEAD_LETTERED = "dead_lettered"
    REJECTED_BY_REVIEWER = "rejected_by_reviewer"


class InfoType(str, Enum):
    """Google Cloud Sensitive Data Protection (DLP) standard infoTypes (`INV-03`)."""
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    US_SOCIAL_SECURITY_NUMBER = "US_SOCIAL_SECURITY_NUMBER"
    CREDIT_CARD_NUMBER = "CREDIT_CARD_NUMBER"
    GCP_API_KEY = "GCP_API_KEY"
    PROJECT_CODENAME = "PROJECT_CODENAME"


class DeidentificationMethod(str, Enum):
    """Techniques for masking sensitive infoTypes."""
    REDACTION = "REDACTION"
    CRYPTO_TOKENIZATION = "CRYPTO_TOKENIZATION"
    MASKING = "MASKING"


class AgentRole(str, Enum):
    """Specialized worker agent roles coordinated by Vertex AI Reasoning Engine."""
    SUPERVISOR = "SupervisorAgent"
    DATA_DISCOVERY = "DataDiscoveryAgent"
    ANALYSIS = "AnalysisAgent"
    ACTION_EXECUTOR = "ActionExecutorAgent"
    COMPLIANCE_AUDITOR = "ComplianceAuditorAgent"


# ============================================================================
# 2. Identity, Zero-Trust & VPC Service Controls Contracts (INV-01, INV-06)
# ============================================================================

class GoogleIdentityContext(BaseModel):
    """Workload Identity Federation context representing caller identity (`INV-01`)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    project_id: str = Field(default="contoso-ai-prod-01")
    service_account_email: str = Field(default="sa-agent-orchestrator@contoso-ai-prod-01.iam.gserviceaccount.com")
    user_email: str = Field(..., min_length=5, description="Caller Google Workspace or Entra Federated UPN")
    user_display_name: str = Field(default="Enterprise Operator")
    roles: list[str] = Field(default_factory=lambda: ["roles/aiplatform.user"])
    workload_identity_pool: str = Field(default="projects/123456789/locations/global/workloadIdentityPools/corp-pool")
    has_valid_oidc_token: bool = Field(default=True)
    vpc_sc_perimeter_id: str = Field(default="accessPolicies/778899/servicePerimeters/sp_vertex_ai_core")


class VpcServiceControlsCheck(BaseModel):
    """Verification record for VPC-SC perimeter egress/ingress policies (`INV-06`)."""
    perimeter_name: str
    source_ip_allowed: bool
    egress_rule_matched: bool
    access_granted: bool
    denial_reason: str | None = None


class CmekEnvelope(BaseModel):
    """Customer-Managed Encryption Key metadata for cryptographic signing (`INV-05`)."""
    key_id: str
    ciphertext_hash: str
    algorithm: str = "GOOGLE_SYMMETRIC_ENCRYPTION"
    encrypted_at: str = Field(default_factory=utc_now_iso)


# ============================================================================
# 3. Model Armor & Adversarial Defense Contracts (INV-02)
# ============================================================================

class ModelArmorVerdict(BaseModel):
    """Google Cloud Model Armor inspection verdict (`REQ-GCP-ARMOR-01`)."""
    safe: bool
    user_prompt_attack_detected: bool = False
    document_attack_detected: bool = False
    system_prompt_leakage_detected: bool = False
    flagged_triggers: list[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.99, ge=0.0, le=1.0)
    latency_ms: float = 4.2


# ============================================================================
# 4. Sensitive Data Protection (DLP) & Grounded Search Contracts (INV-03, INV-04)
# ============================================================================

class DlpFinding(BaseModel):
    """Single sensitive finding detected by Cloud Sensitive Data Protection."""
    info_type: InfoType
    likelihood: Literal["VERY_LIKELY", "LIKELY", "POSSIBLE"] = "VERY_LIKELY"
    original_snippet_hash: str
    replacement_token: str


class DlpSanitizationResult(BaseModel):
    """Output of real-time Cloud DLP de-identification inspection (`REQ-GCP-DLP-01`)."""
    original_length: int
    sanitized_text: str
    findings_count: int
    findings: list[DlpFinding]
    deidentification_method: DeidentificationMethod = DeidentificationMethod.CRYPTO_TOKENIZATION


class GroundedCitation(BaseModel):
    """Attribution metadata from Vertex AI Search or BigQuery Vector Search (`INV-04`)."""
    chunk_id: str
    source_title: str
    source_uri: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    text_segment: str
    dataplex_policy_tags: list[str] = Field(default_factory=list)


class GroundedSearchResult(BaseModel):
    """Consolidated Grounded RAG response with attribution verification (`REQ-GCP-RAG-01`)."""
    query: str
    groundedness_score: float = Field(..., ge=0.0, le=1.0)
    passed_grounding_threshold: bool
    citations: list[GroundedCitation]
    synthesized_response: str
    semantic_cache_hit: bool = False


# ============================================================================
# 5. Reasoning Engine, Multi-Agent Trajectory & HITL Contracts (INV-05)
# ============================================================================

class AgentExecutionStep(BaseModel):
    """Step in the Vertex AI multi-agent supervisor-worker graph (`REQ-GCP-ARCH-01`)."""
    step_order: int
    agent_role: AgentRole
    agent_name: str
    input_summary: str
    output_summary: str
    tool_name: str
    latency_ms: float


class AgenticWorkflowRequest(BaseModel):
    """Inbound request dispatched to the Agentic Cloud Run service."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    workflow_id: str = Field(default="wf-gcp-9901")
    identity: GoogleIdentityContext
    user_prompt: str = Field(..., min_length=5)
    target_spend_usd: float = Field(default=0.0, ge=0.0)
    department: str = Field(default="Corporate Procurement")
    uploaded_document_text: str | None = None
    force_model_tier: ModelTier | None = None
    simulate_upstream_503: bool = False


class HitlApprovalRequest(BaseModel):
    """Human-in-the-Loop authorization payload for paused spend workflows (`INV-05`)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    workflow_id: str
    approved: bool
    approver_email: str = Field(..., min_length=5)
    approver_notes: str = Field(default="Verified budget allocation and compliance in BigQuery.")
    oidc_signature: str = Field(default="oidc-sig-approver-secops-01")


class CloudTraceSpan(BaseModel):
    """OpenTelemetry GenAI span exported to Google Cloud Trace (`INV-08`)."""
    span_id: str
    trace_id: str
    name: str
    department: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_ms: float
    status_code: str = "OK"
    timestamp: str = Field(default_factory=utc_now_iso)


class PubSubMessageEnvelope(BaseModel):
    """Event message dispatched via Cloud Pub/Sub and Eventarc (`INV-07`)."""
    message_id: str
    topic: str
    delivery_attempt: int
    status: Literal["DELIVERED", "RETRYING", "DEAD_LETTERED"]
    dead_letter_reason: str | None = None
    payload: dict[str, Any]
    timestamp: str = Field(default_factory=utc_now_iso)


class AgenticWorkflowResponse(BaseModel):
    """End-to-end response produced by the Agentic Orchestration Platform."""
    workflow_id: str
    status: WorkflowStatus
    selected_model: ModelTier
    routing_rationale: str
    sanitized_prompt: str
    dlp_findings: list[DlpFinding] = Field(default_factory=list)
    model_armor_verdict: ModelArmorVerdict
    vpc_sc_check: VpcServiceControlsCheck
    trajectory: list[AgentExecutionStep] = Field(default_factory=list)
    requires_hitl: bool = False
    approval_token: str | None = None
    cmek_envelope: CmekEnvelope | None = None
    grounding_attribution: GroundedSearchResult | None = None
    pubsub_envelope: PubSubMessageEnvelope | None = None
    total_cost_usd: float = 0.0
    trace_spans: list[CloudTraceSpan] = Field(default_factory=list)
    final_output: str


# ============================================================================
# 6. Observability, FinOps Quotas & 4-Gate Evaluation (INV-08, REQ-GCP-EVAL-01)
# ============================================================================

class FinOpsQuotaMetrics(BaseModel):
    """Departmental token consumption and cost center attribution metrics."""
    department: str
    allocated_budget_usd: float
    current_spend_usd: float
    tokens_consumed: int
    tpm_limit: int
    budget_exceeded: bool
    cost_burn_percent: float


class FourGateEvalReport(BaseModel):
    """Master evaluation report produced by the automated 4-Gate Verification Suite."""
    suite_status: Literal["PASSED", "FAILED"]
    all_gates_passed: bool
    gates: dict[str, Any]
    generated_at: str = Field(default_factory=utc_now_iso)


# ============================================================================
# 7. Multi-Tier Agent Memory & Memorystore Vector Distillation (INV-09, REQ-GCP-MEM-01)
# ============================================================================

class MemoryType(str, Enum):
    """Memory retention tier in Vertex AI agentic architectures."""
    WORKING = "WORKING"
    EPISODIC = "EPISODIC"
    DISTILLED_RULE = "DISTILLED_RULE"


class EpisodicMemoryRecord(BaseModel):
    """Persistent episodic memory record indexed in Cloud Memorystore / Vertex Feature Store."""
    memory_id: str
    tenant_id: str
    user_id: str
    prompt: str
    outcome: str
    action_summary: str
    feedback_sentiment: Literal["POSITIVE", "NEGATIVE", "NEUTRAL"] = "POSITIVE"
    embedding: list[float] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


class DistilledGovernanceRule(BaseModel):
    """Deterministic governance constraint extracted from human feedback cycles."""
    rule_id: str
    tenant_id: str
    category: str
    rule_text: str
    source_workflow_id: str
    created_at: str = Field(default_factory=utc_now_iso)


class MemoryRecallResult(BaseModel):
    """Consolidated memory recall payload with semantic similarity scores."""
    query: str
    recalled_memories: list[EpisodicMemoryRecord] = Field(default_factory=list)
    distilled_rules: list[DistilledGovernanceRule] = Field(default_factory=list)
    top_similarity_score: float = 0.0


# ============================================================================
# 8. BigQuery Continuous Evaluation & Vertex AI GenAI Studio (INV-10, REQ-GCP-BIGQUERY-EVAL-01)
# ============================================================================

class JudgeMetricResult(BaseModel):
    """Single LLM-as-a-Judge evaluation metric score."""
    metric_name: Literal["faithfulness", "answer_relevance", "safety_harm", "latency_efficiency"]
    score: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    passed: bool


class ContinuousEvalRecord(BaseModel):
    """Workflow evaluation trace streamed into BigQuery continuous eval tables."""
    eval_id: str
    workflow_id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    metrics: list[JudgeMetricResult]
    overall_passed: bool
    bigquery_table: str = "contoso_ai_prod.vertex_ai_evaluations.continuous_traces"


class BigQueryStudioQueryResult(BaseModel):
    """Analytics result returned from BigQuery Continuous Evaluation Studio."""
    query_name: str
    sql: str
    rows: list[dict[str, Any]]
    execution_time_ms: float


# ============================================================================
# 9. FastMCP / Model Context Protocol Google Cloud Server (INV-11, REQ-GCP-MCP-01)
# ============================================================================

class McpSensitivityTier(str, Enum):
    """Security tier governing tool execution permissions."""
    READ_ONLY = "READ_ONLY"
    DRAFT_MUTATION = "DRAFT_MUTATION"
    LIVE_SPEND = "LIVE_SPEND"


class McpToolDefinition(BaseModel):
    """Standard Model Context Protocol tool schema."""
    name: str
    description: str
    sensitivity_tier: McpSensitivityTier
    inputSchema: dict[str, Any]


class McpResourceDefinition(BaseModel):
    """Standard Model Context Protocol resource metadata."""
    uri: str
    name: str
    description: str
    mimeType: str = "application/json"


class McpJsonRpcRequest(BaseModel):
    """Standard Model Context Protocol JSON-RPC 2.0 request envelope."""
    jsonrpc: str = "2.0"
    id: str | int
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class McpJsonRpcResponse(BaseModel):
    """Standard Model Context Protocol JSON-RPC 2.0 response envelope."""
    jsonrpc: str = "2.0"
    id: str | int
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


# ============================================================================
# 10. Cloud Run Eventarc A2A & Resilient Circuit Breaker (INV-12, REQ-GCP-A2A-01)
# ============================================================================

class CircuitBreakerState(str, Enum):
    """Tri-state circuit breaker state machine."""
    CLOSED = "CLOSED"
    HALF_OPEN = "HALF_OPEN"
    OPEN = "OPEN"


class A2AMessagePayload(BaseModel):
    """Google Agent-to-Agent (A2A) protocol wire message for Eventarc dispatch."""
    sender_agent: str
    target_agent: str
    intent: str
    context: dict[str, Any]
    trace_id: str
    requires_ack: bool = True
    timestamp: str = Field(default_factory=utc_now_iso)


class CircuitBreakerStatus(BaseModel):
    """Resilient health status and failure isolation record."""
    service_name: str
    state: CircuitBreakerState
    failure_count: int
    success_count: int
    last_failure_timestamp: str | None = None
    active_model_tier: ModelTier
    degradation_active: bool = False


# ============================================================================
# 11. Master 8-Gate Master Evaluation Report (REQ-GCP-EVAL-01)
# ============================================================================

class EightGateEvalReport(BaseModel):
    """Master evaluation report produced by the comprehensive 8-Gate Verification Suite."""
    suite_status: Literal["PASSED", "FAILED"]
    all_gates_passed: bool
    gates: dict[str, Any]
    generated_at: str = Field(default_factory=utc_now_iso)
