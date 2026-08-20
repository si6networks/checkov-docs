# CKV2_GCP_31: Ensure logging is enabled for Dialogflow CX webhooks
## Severity
**MEDIUM** (score: 5.0/10)

Disabled logging on a Dialogflow CX webhook removes an audit trail for webhook invocations, limiting the ability to detect anomalous or malicious calls rather than exposing the webhook itself.

## Summary
This check ensures that Dialogflow CX webhook resources have `enable_stackdriver_logging` set to `true`, so calls to fulfillment webhooks are logged.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_dialogflow_cx_webhook`

## Why it matters
Dialogflow CX webhooks call out to external fulfillment services (often custom backend APIs) to fetch data, perform transactions, or apply business logic mid-conversation. These webhook calls can carry sensitive parameters (user-provided data, session context) to third-party or internal endpoints, and any failures or malicious payload manipulation in that call path can be invisible without logging. Without `enable_stackdriver_logging`, there's no record of webhook invocations, their payloads/responses, latency, or errors — making it difficult to detect webhook abuse, debug integration failures, or investigate a security incident where a webhook endpoint may have been targeted or its responses tampered with (e.g., a compromised backend returning malicious fulfillment text).

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_dialogflow_cx_webhook`:
- **PASS** if `enable_stackdriver_logging` is explicitly set to `true`.
- **FAIL** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_dialogflow_cx_webhook" "webhook" {
  parent       = google_dialogflow_cx_agent.agent.id
  display_name = "order-fulfillment-webhook"

  generic_web_service {
    uri = "https://api.example.com/fulfillment"
  }
  # enable_stackdriver_logging not set -> no webhook call logging
}
```

## Remediated example
```hcl
resource "google_dialogflow_cx_webhook" "webhook" {
  parent                     = google_dialogflow_cx_agent.agent.id
  display_name                = "order-fulfillment-webhook"
  enable_stackdriver_logging  = true

  generic_web_service {
    uri = "https://api.example.com/fulfillment"
  }
}
```

## Remediation steps
1. Set `enable_stackdriver_logging = true` on the `google_dialogflow_cx_webhook` resource.
2. Ensure the webhook's request/response payloads do not leak overly sensitive data into logs, or apply redaction in the fulfillment service itself if needed.
3. Monitor webhook call logs for latency spikes, error rates, or unexpected response content as an early signal of backend compromise or integration issues.
4. This is a non-destructive, in-place configuration change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPDialogFlowCxWebhookLoggingEnabled.json
- GCP docs: https://cloud.google.com/dialogflow/cx/docs/concept/log
