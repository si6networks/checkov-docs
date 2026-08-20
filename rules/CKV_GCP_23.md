# CKV_GCP_23: Ensure Kubernetes Cluster is created with Alias IP ranges enabled
## Severity
**LOW** (score: 2.0/10)

Alias IP ranges primarily affect network addressing/routing design for pod IPs rather than closing a direct attack path, making this mostly a networking best-practice check.

## Summary
This check fails when a `google_container_cluster` does not configure an `ip_allocation_policy` block, meaning the cluster is not using VPC-native (alias IP) networking.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
GKE clusters can run in "routes-based" mode (legacy) or "VPC-native" mode using alias IP ranges. VPC-native clusters assign Pod and Service IP ranges as proper VPC subnet secondary ranges, which enables direct integration with VPC firewall rules, Cloud NAT, VPC Service Controls, and Private Google Access — all of which are needed to apply consistent network-security policy to Pod traffic. Routes-based clusters lack this native integration: Pod IPs aren't first-class VPC citizens, making it harder to apply firewall rules or network security monitoring directly to Pod traffic, and routes-based networking has scaling limits (custom routes quota) that alias IP avoids. Google has deprecated routes-based cluster creation for new clusters, making this both a security and forward-compatibility issue.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` on the key `ip_allocation_policy`:
- **PASS** — the `ip_allocation_policy` block is present (any configuration).
- **FAIL** — the block is absent.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "legacy-net-cluster"
  location = "us-central1"
  # no ip_allocation_policy -> routes-based networking -> FAILS
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "vpc-native-cluster"
  location = "us-central1"

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
}
```

## Remediation steps
1. Add an `ip_allocation_policy` block to the `google_container_cluster` resource, referencing (or letting GKE auto-provision) secondary ranges for Pods and Services.
2. If you manage the VPC subnet in Terraform, define `secondary_ip_range` blocks on the `google_compute_subnetwork` for pods/services and reference their names here; otherwise omit the range names to let GKE auto-assign.
3. **This requires cluster replacement** — networking mode (routes-based vs. VPC-native) cannot be changed in place on an existing cluster. Plan for a new cluster and workload migration, not an in-place `terraform apply`.
4. Verify subnet CIDR sizing accounts for the maximum Pods-per-node setting to avoid running out of Pod IP space at scale.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEAliasIpEnabled.py
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/alias-ips
