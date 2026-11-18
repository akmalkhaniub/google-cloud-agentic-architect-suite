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
9. **INV-09 (Multi-Tier Agent Memory & Memorystore Vector Isolation)**:
   - Agent memory **MUST** adhere to strict tiering (ephemeral working session buffer, persistent episodic storage in Cloud Memorystore Redis Vector Search partitioned by `tenant_id`, and distilled governance rules) with cosine recall threshold $\ge 0.82$.
10. **INV-10 (BigQuery Continuous Evaluation & Pointwise LLM-as-a-Judge)**:
    - All production workflow traces **MUST** continuously stream into BigQuery dataset `vertex_ai_evaluations` and pass Pointwise LLM-as-a-Judge thresholds (Faithfulness $\ge 0.90$, Answer Relevance $\ge 0.90$, Zero Safety Harm).
11. **INV-11 (FastMCP Protocol Standard & Tiered Authorization)**:
    - Model Context Protocol integration **MUST** conform to the standard JSON-RPC 2.0 interface (`ping`, `tools/list`, `resources/list`, `tools/call`) with strict 3-tier authorization (`READ_ONLY`, `DRAFT_MUTATION`, `LIVE_SPEND` requiring valid Workload Identity OIDC tokens).
12. **INV-12 (Eventarc A2A Dispatch & Resilient Circuit Breaker)**:
    - Inter-agent communication **MUST** route through Google Agent-to-Agent (A2A) protocol wire envelopes and enforce a tri-state circuit breaker (`CLOSED` / `HALF_OPEN` / `OPEN`) with automated graceful degradation from Gemini 1.5 Pro to Gemini 1.5 Flash upon repeated upstream failures.
13. **INV-13 (Immutable Prompt Registry, Canary Splitting & PSI Drift Auto-Rollback)**:
    - All production prompt templates **MUST** be pinned by SHA-256 checksums, routed via deterministic Champion/Canary buckets, and automatically rolled back to Champion whenever Population Stability Index (`PSI >= 0.25`) or semantic cosine shift (`>= 0.20`) breaches thresholds.
14. **INV-14 (EU AI Act Risk Controls, GDPR Article 17 Erasure & C2PA Provenance)**:
    - Enterprise AI workloads **MUST** be classified under the EU AI Act risk taxonomy (blocking Prohibited systems and enforcing HITL for High-Risk domains), support cascading GDPR Right-to-Erasure with HMAC-signed certificates, and sign synthetic outputs with verifiable C2PA provenance manifests.
15. **INV-15 (Real-Time SSE Streaming Telemetry & Short-Circuit Isolation)**:
    - Live execution endpoints **MUST** stream structured `text/event-stream` frames for Workload Identity, Model Armor, DLP, and agent handoffs, and immediately terminate the stream with a `BLOCKED` frame upon guardrail violation.
16. **INV-16 (Multi-Region Data Sovereignty & Vertex GSU FinOps Guardrails)**:
    - Cross-border inference egress **MUST** be blocked via deterministic regional routing (`europe-west4`, `us-central1`, `asia-northeast1`), and monthly token commitments **MUST** be evaluated against Vertex AI Provisioned Throughput (GSU) break-even and SaaS gross-margin thresholds.

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
| **`REQ-GCP-MEM-01`** | Pillar 5: Multi-Tier Agent Memory | Cloud Memorystore Redis Vector Search episodic store, cosine similarity thresholding ($\ge 0.82$), tenant isolation, and automated governance rule distillation. | **Advanced:** Agent Memory, State & Context Management |
| **`REQ-GCP-BIGQUERY-EVAL-01`** | Pillar 6: BigQuery Continuous Eval | Pointwise LLM-as-a-Judge evaluation streaming traces to BigQuery with SQL analytics (P95 latency, drift index, and departmental spend). | **Advanced:** MLOps, Model Monitoring & BigQuery Analytics |
| **`REQ-GCP-MCP-01`** | Pillar 7: FastMCP Google Cloud Server | FastMCP JSON-RPC 2.0 server exposing GCP agent tools & resources to external AI coding agents with `LIVE_SPEND` authorization gating. | **Advanced:** Open Protocol Interoperability & MCP Standard |
| **`REQ-GCP-A2A-01`** | Pillar 8: Eventarc A2A & Circuit Breaker | Agent-to-Agent wire protocol dispatcher with self-healing tri-state circuit breaker and automated model cascade degradation (Pro to Flash). | **Advanced:** Multi-Agent Swarms & Resilient Architecture |
| **`REQ-GCP-PROMPT-01`** | Pillar 9: Prompt Registry & Canary Drift | Immutable SHA-256 prompt versioning, deterministic Champion/Canary traffic routing, and automated PSI/Cosine drift rollback. | **Production Ops:** LLMOps, Canary Releases & Drift Guardrails |
| **`REQ-GCP-GOV-01`** | Pillar 10: EU AI Act, GDPR & C2PA | Automated EU AI Act risk classification, cascading GDPR Art. 17 Right-to-Erasure certificates, and tamper-evident C2PA content provenance signing. | **Governance:** EU AI Act, GDPR Privacy & Content Provenance |
| **`REQ-GCP-SSE-01`** | Pillar 11: Real-Time SSE Streaming Bus | Async Server-Sent Events (`text/event-stream`) streaming live security checks, DLP redactions, and multi-agent handoffs to operator consoles. | **UX & Telemetry:** Real-Time Streaming Agent Observability |
| **`REQ-GCP-FINOPS-GSU-01`** | Pillar 12: Sovereignty & GSU FinOps | Multi-region data residency enforcement (`europe-west4`, `us-central1`, `asia-northeast1`) and Vertex AI GSU vs. PAYG FinOps crossover modeling. | **FinOps & Sovereignty:** Cloud Economics & Global Residency |
| **`REQ-GCP-EVAL-01`** | Cross-Cutting: 12-Gate Evals & CI/CD | Comprehensive 12-Gate Automated Verification Suite + Eval-Gated GitHub Actions CI/CD covering all 12 pillars with 100% compliance. | **All:** Enterprise Production Readiness |

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
| `REQ-GCP-MEM-01` | `src/pillars/p5_agent_memory_store.py` | `tests/test_suite.py::test_req_gcp_mem_01_working_memory_and_history`<br/>`tests/test_suite.py::test_req_gcp_mem_02_episodic_recall_cosine_threshold`<br/>`tests/test_suite.py::test_req_gcp_mem_03_governance_rule_distillation` |
| `REQ-GCP-BIGQUERY-EVAL-01` | `src/pillars/p6_bigquery_eval_studio.py` | `tests/test_suite.py::test_req_gcp_bq_01_continuous_evaluation_metrics`<br/>`tests/test_suite.py::test_req_gcp_bq_02_analytics_sql_queries` |
| `REQ-GCP-MCP-01` | `src/pillars/p7_mcp_google_server.py` | `tests/test_suite.py::test_req_gcp_mcp_01_tools_and_resources_list`<br/>`tests/test_suite.py::test_req_gcp_mcp_02_live_spend_authorization_gate` |
| `REQ-GCP-A2A-01` | `src/pillars/p8_a2a_resilient_circuit_breaker.py` | `tests/test_suite.py::test_req_gcp_a2a_01_normal_message_dispatch`<br/>`tests/test_suite.py::test_req_gcp_a2a_02_circuit_breaker_fault_trip_and_degradation` |
| `REQ-GCP-PROMPT-01` | `src/pillars/p9_prompt_registry_canary.py` | `tests/test_suite.py::test_req_gcp_prompt_01_sha256_version_pinning_and_canary_routing`<br/>`tests/test_suite.py::test_req_gcp_prompt_02_psi_drift_triggers_canary_auto_rollback` |
| `REQ-GCP-GOV-01` | `src/pillars/p10_ai_governance_gdpr_c2pa.py` | `tests/test_suite.py::test_req_gcp_gov_01_eu_ai_act_risk_classification`<br/>`tests/test_suite.py::test_req_gcp_gov_02_gdpr_article_17_cascading_erasure`<br/>`tests/test_suite.py::test_req_gcp_gov_03_c2pa_provenance_signing_and_tamper_detection` |
| `REQ-GCP-SSE-01` | `src/pillars/p11_sse_streaming_bus.py` | `tests/test_suite.py::test_req_gcp_sse_01_streaming_events_ordered_lifecycle`<br/>`tests/test_suite.py::test_req_gcp_sse_02_streaming_short_circuit_on_model_armor_block`<br/>`tests/test_suite.py::test_req_gcp_sse_03_fastapi_sse_endpoint_stream` |
| `REQ-GCP-FINOPS-GSU-01` | `src/pillars/p12_sovereignty_gsu_finops.py` | `tests/test_suite.py::test_req_gcp_finops_02_multi_region_sovereignty_routing`<br/>`tests/test_suite.py::test_req_gcp_finops_03_gsu_vs_payg_crossover_economics` |
| `REQ-GCP-EVAL-01` | `src/evals/runner.py` | `tests/test_suite.py::test_req_gcp_eval_01_four_gate_evaluation_suite`<br/>`tests/test_suite.py::test_req_gcp_eval_02_eight_gate_evaluation_suite`<br/>`tests/test_suite.py::test_req_gcp_eval_03_twelve_gate_master_evaluation_suite` |
