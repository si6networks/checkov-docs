# CKV_GCP_1: Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters

## Severity
**LOW** (score: 2.0/10)

Disabling Stackdriver logging on a GKE cluster removes the audit trail needed to detect, investigate, and respond to malicious activity or compromise within the cluster.

## Summary
This check ensures that a `google_container_cluster` (GKE) resource has Stackdriver (Cloud Logging) enabled, rather than explicitly disabled via `logging_service = "none"`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_container_cluster`

## Why it matters
GKE clusters generate control-plane and workload logs (API server audit events, scheduler decisions, kubelet/container stdout/stderr) that are essential for security investigations, operational troubleshooting, and compliance evidence. If `logging_service` is set to `"none"`:

- **No forensic trail**: In the event of a compromised workload, credential misuse, or unauthorized `kubectl` access, there is no log record in Cloud Logging to reconstruct what happened — logs are simply not shipped anywhere and are lost when pods/nodes are recycled.
- **No centralized alerting**: Security and ops tooling that relies on Cloud Logging sinks (e.g., log-based metrics, Cloud Monitoring alerts, SIEM export via Pub/Sub) receives nothing from this cluster, creating a monitoring blind spot alongside otherwise-instrumented clusters.
- **Compliance gaps**: Frameworks such as CIS GKE Benchmark, PCI-DSS, and SOC 2 require retained, centralized audit logging for systems handling sensitive workloads; a cluster with logging disabled cannot satisfy these controls.
- **Delayed incident detection**: Without shipped logs, anomalous behavior (privilege escalation attempts, unusual API calls, crash loops indicating exploitation attempts) can go unnoticed until much later, if at all.

## How Checkov evaluates this
The check (`GKEClusterLogging`) is a negative-value check on the `logging_service` attribute of `google_container_cluster`:
- **FAILS** if `logging_service` is explicitly set to `"none"`.
- **PASSES** for any other value, including the default (Google's current default is `logging.googleapis.com/kubernetes`, i.e., enabled) or an explicit setting like `"logging.googleapis.com/kubernetes"`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  logging_service = "none"

  initial_node_count = 3
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  logging_service = "logging.googleapis.com/kubernetes"

  initial_node_count = 3
}
```

## Remediation steps
1. Remove any explicit `logging_service = "none"` from the `google_container_cluster` resource.
2. Set `logging_service` to `"logging.googleapis.com/kubernetes"` (recommended, GKE-native logging) or simply omit the attribute to accept the provider default.
3. If using GKE's newer `logging_config` block (available in recent `google` provider versions) instead of the legacy `logging_service` attribute, ensure it enables at least `SYSTEM_COMPONENTS` and ideally `WORKLOADS` components.
4. Apply the change — enabling logging on an existing cluster is a non-disruptive, in-place update (no node replacement required).
5. Verify logs are flowing by checking Cloud Logging in the GCP Console shortly after the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEClusterLogging.py
- GCP GKE logging documentation: https://cloud.google.com/kubernetes-engine/docs/how-to/configure-logging
