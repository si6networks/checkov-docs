# CKV_GCP_26: Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network
## Severity
**LOW** (score: 2.0/10)

Missing VPC Flow Logs removes network traffic visibility needed to detect and investigate lateral movement, exfiltration, or reconnaissance within a subnet, a logging/monitoring gap rather than a direct exposure.

## Summary
This check fails when a `google_compute_subnetwork` does not configure a `log_config` block enabling VPC Flow Logs, unless the subnet's `purpose` makes flow logs inapplicable.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_compute_subnetwork`
- **Check type:** resource

## Why it matters
VPC Flow Logs record metadata about IP traffic (source/destination, ports, protocol, byte/packet counts, timestamps) traversing a subnet's VNICs. Without them, you have no network-level visibility for incident response (e.g., "did anything communicate with this known-bad IP?"), no baseline for anomaly detection, and no forensic trail after a compromise. Flow logs are frequently a compliance requirement (PCI-DSS, SOC 2, FedRAMP) and are foundational input for network security monitoring tools, threat-hunting, and post-incident root-cause analysis. Omitting flow logs means a breach investigation may have to rely solely on application logs (if any exist), missing lateral-movement or exfiltration evidence at the network layer.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the key `log_config` (matching `ANY_VALUE`), with a special exception:
- If the subnetwork's `purpose` is one of `INTERNAL_HTTPS_LOAD_BALANCER`, `REGIONAL_MANAGED_PROXY`, or `GLOBAL_MANAGED_PROXY`, the check returns `UNKNOWN` — flow logs cannot be enabled on these proxy-only subnet purposes, so the check is skipped as not applicable.
- Otherwise:
  - **PASS** — `log_config` block is present.
  - **FAIL** — `log_config` is absent.

## Non-compliant example
```hcl
resource "google_compute_subnetwork" "gke_subnet" {
  name          = "gke-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = "us-central1"
  network       = google_compute_network.vpc.id
  # no log_config -> FAILS
}
```

## Remediated example
```hcl
resource "google_compute_subnetwork" "gke_subnet" {
  name          = "gke-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = "us-central1"
  network       = google_compute_network.vpc.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata              = "INCLUDE_ALL_METADATA"
  }
}
```

## Remediation steps
1. Add a `log_config` block to every `google_compute_subnetwork` that isn't a proxy-only subnet (`INTERNAL_HTTPS_LOAD_BALANCER`/`REGIONAL_MANAGED_PROXY`/`GLOBAL_MANAGED_PROXY`).
2. Tune `flow_sampling` (0.0–1.0) to balance log volume/cost against visibility — 0.5 or 1.0 for security-sensitive subnets, lower for high-throughput/low-risk internal subnets.
3. Set `metadata = "INCLUDE_ALL_METADATA"` if you need full context (instance name, region, etc.) for SIEM ingestion; use `EXCLUDE_ALL_METADATA` only if minimizing log volume is critical.
4. Route flow logs to Cloud Logging and export to your SIEM (Chronicle, Splunk, BigQuery) via a log sink for retention and analysis.
5. This is a metadata-only change and applies without recreating the subnet.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleSubnetworkLoggingEnabled.py
- GCP docs: https://cloud.google.com/vpc/docs/flow-logs
