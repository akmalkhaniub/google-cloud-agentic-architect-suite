# Specification: Google Cloud Professional Agentic Architect Suite (`SPECIFICATION.md`)

## 1. Architectural Constitution & System Invariants

1. **INV-01 (Zero Long-Lived Credentials & Workload Identity Federation)**:
   - Every service invocation across Vertex AI, Cloud Storage, BigQuery, and external endpoints **MUST** authenticate via short-lived Google Cloud Workload Identity Federation tokens (OIDC) or Service Account impersonation with least-privilege IAM roles (`roles/aiplatform.user`, `roles/dlp.user`). Long-lived service account JSON keys are strictly prohibited.
2. **INV-02 (Model Armor & Prompt Injection Isolation)**:
   - Every inbound prompt and external document ingested into Gemini 1.5 Pro/Flash **MUST** be pre-screened by Google Cloud Model Armor. Any payload containing Direct User Prompt Injections (UPIA), Cross-Prompt Indirect Injections (XPIA), or System Prompt Extraction **MUST** halt graph execution immediately with a security block event before any downstream tool invocation.
3. **INV-03 (Sensitive Data Protection & Automated Tokenization)**:
   - All inbound conversational turns and document extracts **MUST** be inspected via Google Cloud Sensitive Data Protection (Cloud DLP). Sensitive infoTypes (`EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SOCIAL_SECURITY_NUMBER`, `CREDIT_CARD_NUMBER`, `GCP_API_KEY`) **MUST** be de-identified/masked via cryptographic tokenization or redaction before entering LLM reasoning context or persistent telemetry.
4. **INV-04 (Grounded RAG & Citation Attribution Gate)**:
   - Enterprise search queries across Vertex AI Search and BigQuery Vector Search **MUST** enforce Dataplex fine-grained column/row access policy tags and maintain a verified Groundedness confidence score of $\ge 0.85$. Unattributed or low-confidence claims **MUST** trigger deterministic fallback or escalation.
5. **INV-05 (Human-in-the-Loop & Mutating Spend Gating)**:
   - Any agent action that involves high-risk actions (`LIVE_SPEND > $5,000 USD` or permanent records mutation) **MUST** pause the execution graph, record an immutable Cloud Audit Log entry, and require explicit cryptographic reviewer authorization before dispatch.
6. **INV-06 (VPC Service Controls & Egress Boundary)**:
   - Production agent workloads **MUST** enforce VPC Service Controls (VPC-SC) service perimeters. Data flow between Vertex AI, Cloud Run, Cloud Storage, and BigQuery is isolated from unauthorized external internet egress.
7. **INV-07 (Durable Pub/Sub Eventarc Self-Healing & DLQ)**:
   - Transient cloud errors (`HTTP 429 Quota Exceeded`, `HTTP 503 Service Unavailable`) **MUST** execute exponential backoff retry policies. Unrecoverable failures exceeding 3 retry cycles **MUST** be dead-lettered to an isolated Cloud Pub/Sub Dead-Letter Queue (`$DeadLetterQueue`) for human review and replay.
8. **INV-08 (OpenTelemetry to Cloud Trace Observability)**:
   - Every graph execution, supervisor-to-worker handoff, and tool execution **MUST** emit structured OpenTelemetry GenAI (`gen_ai.*`) spans with department cost-center attribution, queryable via Google Cloud Trace and Cloud Logging.

---

## 2. Traceable Requirements Catalog

| Requirement ID | Architectural Pillar | Description & Capabilities | Certification Mapping |
| :--- | :--- | :--- | :--- |
| **`REQ-GCP-ARCH-01`** | Pillar 1: Vertex AI Reasoning Engine | Multi-agent supervisor-worker graph with Gemini 1.5 Pro vs. Flash cascade routing, structured JSON function declarations, and Cloud Run gVisor sandboxed execution. | **Core:** Vertex AI Agent Builder & Reasoning Engine |
| **`REQ-GCP-SEC-01`** | Pillar 2: Zero-Trust & Workload Identity | Keyless Workload Identity Federation, Service Account OBO impersonation, VPC Service Controls boundary validation, and Cloud KMS CMEK envelope encryption. | **Core:** Google Cloud Security & Identity Architecture |
| **`REQ-GCP-ARMOR-01`** | Pillar 2: Model Armor Guardrails | Multi-stage Model Armor inspection blocking UPIA, document XPIA, and system prompt leakage before reaching LLM reasoning context. | **Core:** Responsible AI, Security & Model Armor |
| **`REQ-GCP-DLP-01`** | Pillar 3: Sensitive Data Protection | Real-time Cloud DLP inspection, infoType classification (150+ types), and automated cryptographic masking/tokenization. | **Core:** Data Governance, Privacy & Compliance |
| **`REQ-GCP-RAG-01`** | Pillar 3: Grounded Enterprise RAG | Vertex AI Search datastores + BigQuery Vector Search with Dataplex column policy tags, strict grounding citation attribution ($\ge 0.85$), and APIM semantic caching. | **Core:** Enterprise RAG, Grounding & Dataplex |
| **`REQ-GCP-HITL-01`** | Pillar 3: Human-in-the-Loop Gating | Graph checkpointing, pause/resume state machine for high-spend actions ($> \$5,000$), cryptographic approval signature verification, and Cloud Audit Logging. | **Core:** Human-in-the-Loop & Auditability |
| **`REQ-GCP-RES-01`** | Pillar 4: Pub/Sub DLQ & Eventarc | Asynchronous Cloud Pub/Sub integration, Eventarc triggers, exponential backoff for transient 429/503 errors, and automatic Dead-Letter Queue routing. | **Core:** Distributed Resiliency & Eventarc |
| **`REQ-GCP-OBS-01`** | Pillar 4: Cloud Trace & FinOps | Distributed OpenTelemetry `gen_ai.*` tracing to Google Cloud Trace, Cloud Monitoring metrics, department cost center attribution, and quota tracking. | **Core:** Full-Stack Observability & FinOps |
| **`REQ-GCP-EVAL-01`** | Cross-Cutting: 4-Gate Evals | Automated 4-Gate Evaluation Suite (Deterministic Math/DLP, Multi-Agent Trajectory/DLQ, Model Armor/VPC-SC, Cloud Trace FinOps Scorecard). | **All:** Enterprise Production Readiness |

---

## 3. Requirement to Artifact Traceability Matrix

| Requirement ID | Primary Implementation | Verification Test |
| :--- | :--- | :--- |
| `REQ-GCP-ARCH-01` | `src/pillars/p1_reasoning_orchestrator.py` | `tests/test_suite.py::test_req_gcp_arch_01_multi_agent_reasoning` |
| `REQ-GCP-SEC-01` | `src/pillars/p2_zero_trust_model_armor.py` | `tests/test_suite.py::test_req_gcp_sec_01_workload_identity_and_vpc_sc` |
| `REQ-GCP-ARMOR-01` | `src/pillars/p2_zero_trust_model_armor.py` | `tests/test_suite.py::test_req_gcp_armor_01_model_armor_prompt_shields` |
| `REQ-GCP-DLP-01` | `src/pillars/p3_dlp_governance_rag.py` | `tests/test_suite.py::test_req_gcp_dlp_01_sensitive_data_protection` |
| `REQ-GCP-RAG-01` | `src/pillars/p3_dlp_governance_rag.py` | `tests/test_suite.py::test_req_gcp_rag_01_vertex_search_and_dataplex` |
| `REQ-GCP-HITL-01` | `src/pillars/p3_dlp_governance_rag.py` | `tests/test_suite.py::test_req_gcp_hitl_01_adaptive_approval_checkpoint` |
| `REQ-GCP-RES-01` | `src/pillars/p4_resiliency_observability.py` | `tests/test_suite.py::test_req_gcp_res_01_pubsub_retry_and_dlq` |
| `REQ-GCP-OBS-01` | `src/pillars/p4_resiliency_observability.py` | `tests/test_suite.py::test_req_gcp_obs_01_cloud_trace_and_finops` |
| `REQ-GCP-EVAL-01` | `src/evals/runner.py` | `tests/test_suite.py::test_req_gcp_eval_01_four_gate_evaluation_suite` |
