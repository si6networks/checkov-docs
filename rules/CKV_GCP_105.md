# CKV_GCP_105: Ensure Datafusion has stack driver monitoring enabled

## Severity
**LOW** (score: 2.0/10)

Missing Stackdriver monitoring primarily impacts operational visibility and availability rather than closing a direct confidentiality or integrity attack path.

## Summary
This check ensures that a `google_data_fusion_instance` resource has `enable_stackdriver_monitoring` set to `true`, so Cloud Monitoring (Stackdriver) metrics are collected for the Data Fusion instance.

## Applicability
- **IaC framework**: Terraform
- **Resource type**: `google_data_fusion_instance`
- **Attribute inspected**: `enable_stackdriver_monitoring`

## Why it matters
Cloud Data Fusion instances run continuously and orchestrate pipelines that move and transform data. Without Stackdriver monitoring enabled:

- **No visibility into instance health or resource pressure**: Metrics such as CPU/memory utilization, pipeline execution counts, and failure rates are not collected centrally, so degraded performance or resource exhaustion (which can cause silent pipeline failures or data delays) may go unnoticed until it causes a business-visible incident.
- **No automated alerting possible**: Cloud Monitoring alerting policies depend on metrics being reported; without this flag, teams cannot build proactive alerts for instance downtime, pipeline SLA breaches, or anomalous behavior that might indicate compromise or misconfiguration.
- **Slower incident response**: When a data pipeline appears to stop delivering data downstream, the absence of monitoring metrics forces responders to investigate blind, extending mean-time-to-detect and mean-time-to-resolve for data availability incidents.
- **Undermines SRE/observability practices**: Organizations that mandate golden-signal monitoring (latency, traffic, errors, saturation) across critical infrastructure cannot meet that bar for a Data Fusion instance running with monitoring disabled.

## How Checkov evaluates this
The check (`DataFusionStackdriverMonitoring`) is a positive-value check on the `enable_stackdriver_monitoring` attribute:
- **PASSES** if `enable_stackdriver_monitoring = true`.
- **FAILS** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_data_fusion_instance" "pipeline_hub" {
  name    = "etl-hub"
  region  = "us-central1"
  type    = "BASIC"

  enable_stackdriver_logging    = true
  enable_stackdriver_monitoring = false
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
1. Add or update `enable_stackdriver_monitoring = true` on the `google_data_fusion_instance` resource.
2. Apply the change (typically an in-place update; verify against your provider version for any replacement behavior).
3. Configure Cloud Monitoring alerting policies on relevant Data Fusion metrics (instance availability, pipeline failure counts) once monitoring data starts flowing.
4. Pair with `enable_stackdriver_logging = true` (see CKV_GCP_104) for combined logs-plus-metrics observability.
5. Include the Data Fusion instance in existing dashboards/on-call runbooks so the newly available metrics are actually used operationally, not just collected.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataFusionStackdriverMonitoring.py
- GCP Cloud Data Fusion documentation: https://cloud.google.com/data-fusion/docs
