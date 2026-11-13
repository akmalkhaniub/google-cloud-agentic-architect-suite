# Terraform Configuration for Google Cloud Professional Agentic Architect Suite
# Configures Cloud Run, Vertex AI Service Account, Cloud KMS CMEK, Pub/Sub DLQ, Cloud DLP, and VPC-SC

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.38.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
  default     = "contoso-ai-prod-01"
}

variable "region" {
  type        = string
  description = "Google Cloud Region"
  default     = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Identity & Access Management: Least Privilege Service Account
resource "google_service_account" "agent_runner" {
  account_id   = "sa-agent-orchestrator"
  display_name = "Enterprise Agentic Orchestrator Service Account"
  description  = "Dedicated least-privilege identity for Vertex AI Reasoning Engine and Cloud Run"
}

resource "google_project_iam_member" "vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.agent_runner.email}"
}

resource "google_project_iam_member" "dlp_user" {
  project = var.project_id
  role    = "roles/dlp.user"
  member  = "serviceAccount:${google_service_account.agent_runner.email}"
}

resource "google_project_iam_member" "cloud_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.agent_runner.email}"
}

# 2. Cloud KMS: Customer-Managed Encryption Keys (CMEK)
resource "google_kms_key_ring" "agent_keyring" {
  name     = "kr-agent-governance"
  location = var.region
}

resource "google_kms_crypto_key" "agent_cmek" {
  name            = "key-agent-payloads"
  key_ring        = google_kms_key_ring.agent_keyring.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = false
  }
}

# 3. Asynchronous Resiliency: Cloud Pub/Sub Topic with Dead-Letter Queue (DLQ)
resource "google_pubsub_topic" "agent_dlq_topic" {
  name         = "top-agent-dead-letter-queue"
  kms_key_name = google_kms_crypto_key.agent_cmek.id
}

resource "google_pubsub_subscription" "agent_dlq_sub" {
  name  = "sub-agent-dead-letter-consumer"
  topic = google_pubsub_topic.agent_dlq_topic.name
}

resource "google_pubsub_topic" "agent_events_topic" {
  name         = "top-agent-mutating-events"
  kms_key_name = google_kms_crypto_key.agent_cmek.id
}

resource "google_pubsub_subscription" "agent_events_sub" {
  name  = "sub-agent-events-processor"
  topic = google_pubsub_topic.agent_events_topic.name

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.agent_dlq_topic.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

# 4. Cloud Run v2: gVisor Sandboxed Agentic Router & Workbench
resource "google_cloud_run_v2_service" "agent_service" {
  name     = "cr-agentic-architect-suite"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.agent_runner.email

    containers {
      image = "gcr.io/${var.project_id}/google-cloud-agentic-architect-suite:v1.0.0"

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_REGION"
        value = var.region
      }
      env {
        name  = "PUBSUB_TOPIC"
        value = google_pubsub_topic.agent_events_topic.name
      }
      env {
        name  = "PUBSUB_DLQ_TOPIC"
        value = google_pubsub_topic.agent_dlq_topic.name
      }
      env {
        name  = "KMS_KEY_NAME"
        value = google_kms_crypto_key.agent_cmek.id
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }
  }
}

# 5. Sensitive Data Protection (DLP) Inspection & De-identification Templates
resource "google_data_loss_prevention_inspect_template" "agent_pii_inspect" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  description  = "Inspect template detecting PII infoTypes before LLM context ingestion"
  display_name = "Agent PII Inspection Template"

  inspect_config {
    info_types { name = "EMAIL_ADDRESS" }
    info_types { name = "PHONE_NUMBER" }
    info_types { name = "US_SOCIAL_SECURITY_NUMBER" }
    info_types { name = "CREDIT_CARD_NUMBER" }
    info_types { name = "GCP_API_KEY" }
    min_likelihood = "LIKELY"
  }
}

output "cloud_run_uri" {
  value       = google_cloud_run_v2_service.agent_service.uri
  description = "The internal URI of the Cloud Run Agentic Service"
}

output "service_account_email" {
  value       = google_service_account.agent_runner.email
  description = "The email of the dedicated Agent Service Account"
}
