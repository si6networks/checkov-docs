# CKV_GCP_8: Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters
## Severity
**LOW** (score: 2.0/10)

Disabling cluster monitoring is a detection/observability gap that delays recognition of anomalous, compromise-related resource activity rather than a direct exploitable weakness.

## Summary
This check ensures a GKE cluster has Cloud Monitoring (formerly Stackdriver Monitoring) enabled rather than explicitly disabled.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Cluster-level monitoring provides visibility into node and control-plane health, resource utilization, and operational anomalies. Disabling it (`monitoring_service = "none"`) removes this telemetry entirely, which has direct security implications: without monitoring data, unusual resource consumption patterns that often accompany an active compromise (e.g., cryptomining after a container escape, unexpected scaling, node resource exhaustion from a runaway/malicious process) go unnoticed until they cause a visible outage or cost spike. It also hampers incident response and root-cause analysis after the fact, since there's no historical metrics baseline to compare against. This check is specifically about monitoring; combine it with GKE audit/logging configuration for full observability.

## How Checkov evaluates this
Checkov reads the `monitoring_service` attribute (index `0`) on `google_container_cluster`. This is a negative-value check: if `monitoring_service == "none"`, the check FAILS. Any other value — e.g., `"monitoring.googleapis.com/kubernetes"`, `"monitoring.googleapis.com"`, or the attribute left unset (GKE enables monitoring by default) — PASSES.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  monitoring_service = "none"
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  monitoring_service = "monitoring.googleapis.com/kubernetes"
}
```

## Remediation steps
1. Remove `monitoring_service = "none"`, or set it explicitly to `"monitoring.googleapis.com/kubernetes"` (the current GKE-native monitoring integration).
2. For more granular control on newer provider versions, consider using the `monitoring_config` block instead, which allows selecting specific component types (SYSTEM_COMPONENTS, WORKLOADS, etc.) rather than the older all-or-nothing `monitoring_service` string.
3. Confirm the Cloud Monitoring API is enabled on the project and that the cluster's service account has the necessary `roles/monitoring.metricWriter` permission (default node service account has this by default).
4. This is a live cluster update; it does not require node pool recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEMonitoringEnabled.py)
- [Google Cloud: GKE observability overview](https://cloud.google.com/kubernetes-engine/docs/concepts/about-monitoring)
