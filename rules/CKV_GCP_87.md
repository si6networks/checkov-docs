# CKV_GCP_87: Ensure Data Fusion instances are private
## Severity
**HIGH** (score: 7.0/10)

A publicly reachable Data Fusion instance exposes a data-integration/ETL control plane that can access multiple downstream data sources, representing broad network exposure of a sensitive service.

## Summary
This check requires `google_data_fusion_instance` resources to set `private_instance = true`, so the Data Fusion instance's networking is not exposed via a public IP.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_data_fusion_instance`
- **Check type:** resource (attribute-value check)

## Why it matters
Cloud Data Fusion instances orchestrate ETL/ELT data pipelines and typically have broad access to source and destination data stores (BigQuery, Cloud Storage, databases) via configured connections and service account credentials. A public (non-private) Data Fusion instance exposes its management/UI endpoint over the internet, making it a target for credential-stuffing, exploitation of unpatched vulnerabilities, or unauthorized pipeline modification — any of which could be used to redirect, exfiltrate, or corrupt the data flowing through pipelines it manages. Running the instance in private mode confines access to your VPC via VPC peering, so only hosts within your network perimeter (subject to your firewall rules and IAM) can reach the instance, consistent with a defense-in-depth posture for a component that has broad data-plane reach.

## How Checkov evaluates this
The check (`DataFusionPrivateInstance`, a `BaseResourceValueCheck`) inspects the `private_instance` attribute on `google_data_fusion_instance`.
- **PASS**: `private_instance = true`.
- **FAIL**: `private_instance` is absent or `false` (default is public access enabled).

## Non-compliant example
```hcl
resource "google_data_fusion_instance" "pipeline" {
  name    = "pipeline-instance"
  region  = "us-central1"
  type    = "BASIC"
  # private_instance not set -> defaults to public
}
```

## Remediated example
```hcl
resource "google_data_fusion_instance" "pipeline" {
  name             = "pipeline-instance"
  region           = "us-central1"
  type             = "BASIC"
  private_instance = true

  network_config {
    network       = google_compute_network.data_vpc.name
    ip_allocation = google_compute_global_address.data_fusion_range.address
  }
}
```

## Remediation steps
1. Set `private_instance = true` on the `google_data_fusion_instance` resource.
2. Add a `network_config` block specifying the VPC network and a reserved `/22` IP range (via `google_compute_global_address` with `purpose = "VPC_PEERING"`) for VPC peering — private instances require this peering setup.
3. Note: `private_instance` cannot typically be toggled on an existing instance without recreation; this is a disruptive change requiring instance replacement and pipeline redeployment.
4. Ensure any client/CI systems that reach the Data Fusion UI/API are on, or connected to, the peered VPC (e.g., via VPN/Interconnect or a bastion) after the change.
5. Confirm the instance's `type` (BASIC/ENTERPRISE/DEVELOPER) supports private instances in your target region before applying.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataFusionPrivateInstance.py
- GCP docs: https://cloud.google.com/data-fusion/docs/concepts/network-architecture
