# CKV2_GCP_29: Ensure logging is enabled for Dialogflow agents
## Severity
**MEDIUM** (score: 5.0/10)

Disabled logging on a Dialogflow agent removes an audit trail of conversational interactions, hindering detection and investigation of abuse or data-handling issues rather than enabling a direct compromise.

## Summary
This check ensures that Dialogflow ES agents have `enable_logging` set to `true`, so conversation and interaction events are recorded.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_dialogflow_agent`

## Why it matters
Dialogflow agents power conversational interfaces (chatbots, voice assistants, IVR systems) that can process user-submitted data, including PII, account details, or transaction requests. Without logging enabled, there is no audit trail of what the agent processed, which intents were triggered, or how requests were handled — this severely hampers incident response (unable to determine if the agent was manipulated via prompt/intent injection, or whether an abuse pattern occurred), troubleshooting (no visibility into misrouted or failed conversations), and compliance requirements that mandate retaining interaction logs. Enabling logging integrates agent activity into Cloud Logging, where it can be monitored, alerted on, and retained per organizational policy.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_dialogflow_agent`:
- **PASS** if `enable_logging` is explicitly set to `true`.
- **FAIL** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_dialogflow_agent" "agent" {
  display_name    = "customer-support-bot"
  default_language_code = "en"
  time_zone       = "America/New_York"
  # enable_logging not set -> no interaction logging
}
```

## Remediated example
```hcl
resource "google_dialogflow_agent" "agent" {
  display_name          = "customer-support-bot"
  default_language_code = "en"
  time_zone             = "America/New_York"
  enable_logging        = true
}
```

## Remediation steps
1. Set `enable_logging = true` on the `google_dialogflow_agent` resource.
2. Verify the project has Cloud Logging enabled and appropriate log retention/export (e.g., to a log sink/BigQuery) configured for compliance needs.
3. Review data handled by the agent for PII before enabling logging broadly, and apply appropriate log access controls/redaction if conversations may contain sensitive user data.
4. This is a non-destructive, in-place configuration change with no expected downtime.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPDialogFlowAgentLoggingEnabled.json
- GCP docs: https://cloud.google.com/dialogflow/es/docs/how/logging
