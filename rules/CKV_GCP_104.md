# CKV_GCP_104: Ensure Datafusion has stack driver logging enabled

## Severity
**LOW** (score: 2.0/10)

Missing Stackdriver logging on a Data Fusion instance reduces visibility into pipeline activity, weakening the ability to detect misuse, misconfiguration, or compromise of data pipelines.

## Summary
This check ensures that a `google_data_fusion_instance` resource has `enable_stackdriver_logging` set to `true`, so Cloud Data Fusion pipeline execution logs are shipped to Cloud Logging (Stackdriver).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_data_fusion_instance`
- **Attribute inspected**: `enable_stackdriver_logging`

## Why it matters
Cloud Data Fusion is a fully managed data integration service that orchestrates ETL/ELT pipelines, often processing sensitive or regulated data as it moves between sources (databases, APIs, files) and sinks (BigQuery, GCS, other systems). Without Stackdriver logging enabled:

- **No audit trail for pipeline execution**: There is no centralized record of what pipeline ran, when, what data sources/sinks it touched, or whether it succeeded/failed, making it difficult to investigate data integrity incidents or unauthorized pipeline changes.
- **Delayed detection of pipeline failures or tampering**: If a malicious or buggy pipeline modification silently corrupts, drops, or misroutes data, there's no log-based alerting mechanism to catch it, since nothing is being shipped to the monitoring layer teams rely on.
- **Compliance and data lineage gaps**: Many compliance frameworks require verifiable logs of when and how sensitive data was transformed or moved; a Data Fusion instance without logging enabled undermines demonstrable data lineage and audit-readiness.
- **Operational blind spot**: Troubleshooting failed or slow pipelines becomes significantly harder without centralized logs, increasing mean-time-to-resolution for production data pipeline incidents.

## How Checkov evaluates this
The check (`DataFusionStackdriverLogs`) is a positive-value check on the `enable_stackdriver_logging` attribute:
- **PASSES** if `enable_stackdriver_logging = true`.
- **FAILS** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_data_fusion_instance" "pipeline_hub" {
  name    = "etl-hub"
  region  = "us-central1"
  type    = "BASIC"

  enable_stackdriver_logging    = false
  enable_stackdriver_monitoring = true
}
```

## Remediated example
```hcl
resource "google_data_fusion_instance" "pipeline_hub" {
  name    = "etl-hub"
  region  = "us-central1"
  type    = "BASIC"

  enable_stackdriver_logging    = true
  enable_stackdriver_monitoring = true
}
```

## Remediation steps
1. Add or update `enable_stackdriver_logging = true` on the `google_data_fusion_instance` resource.
2. Apply the change — this is typically an in-place update, but confirm against your `google` provider version's documented update behavior, since some Data Fusion attributes can force replacement.
3. Verify logs begin appearing in Cloud Logging under the Data Fusion resource type after the next pipeline run.
4. Consider setting up log-based alerting or a log sink (e.g., to BigQuery or a SIEM) for pipeline failure events once logging is enabled.
5. Pair with `enable_stackdriver_monitoring = true` (see CKV_GCP_105) for full observability coverage.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataFusionStackdriverLogs.py
- GCP Cloud Data Fusion documentation: https://cloud.google.com/data-fusion/docs
