# CKV2_GCP_30: Ensure logging is enabled for Dialogflow CX agents
## Severity
**MEDIUM** (score: 5.0/10)

Disabled Stackdriver logging on a Dialogflow CX agent removes visibility into agent activity, weakening detection and forensic capability for that conversational surface rather than creating a direct exploit path.

## Summary
This check ensures that Dialogflow CX agents have `enable_stackdriver_logging` set to `true`, so conversation and interaction events are sent to Cloud Logging (formerly Stackdriver).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_dialogflow_cx_agent`

## Why it matters
Dialogflow CX (the newer, flow-based version of Dialogflow) drives complex conversational applications that may process customer PII, authentication flows, and transactional intents. Without Cloud Logging enabled, operators have no centralized, queryable record of agent interactions — making it difficult to detect abuse (e.g., an attacker probing intents to enumerate valid accounts or extract information), diagnose broken conversation flows, or meet audit/compliance requirements for retaining records of automated customer interactions. Enabling logging feeds interaction data into the same centralized logging/monitoring/alerting pipeline used for the rest of the GCP environment.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_dialogflow_cx_agent`:
- **PASS** if `enable_stackdriver_logging` is explicitly set to `true`.
- **FAIL** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_dialogflow_cx_agent" "agent" {
  display_name = "support-cx-agent"
  location     = "us-central1"
  default_language_code = "en"
  time_zone    = "America/New_York"
  # enable_stackdriver_logging not set -> no logging
}
```

## Remediated example
```hcl
resource "google_dialogflow_cx_agent" "agent" {
  display_name              = "support-cx-agent"
  location                   = "us-central1"
  default_language_code      = "en"
  time_zone                  = "America/New_York"
  enable_stackdriver_logging = true
}
```

## Remediation steps
1. Set `enable_stackdriver_logging = true` on the `google_dialogflow_cx_agent` resource.
2. Confirm Cloud Logging is enabled for the project and configure log sinks/retention appropriate for the sensitivity of conversation data.
3. Review whether logged conversations may contain PII and apply redaction or restricted log-viewer access as needed.
4. This is a non-destructive, in-place configuration change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPDialogFlowCxAgentLoggingEnabled.json
- GCP docs: https://cloud.google.com/dialogflow/cx/docs/concept/log
