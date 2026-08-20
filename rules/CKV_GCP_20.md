# CKV_GCP_20: Ensure master authorized networks is set to enabled in GKE clusters
## Severity
**LOW** (score: 2.0/10)

Without master authorized networks restricting source IPs, the GKE control plane API becomes reachable from any address, materially broadening the attack surface for an administrative interface even though it doesn't guarantee public exposure alone.

## Summary
This check fails when a `google_container_cluster` does not configure a `master_authorized_networks_config` block at all — i.e., the control plane has no IP allowlist restricting who can reach the Kubernetes API server.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
Without `master_authorized_networks_config`, the GKE control plane's public endpoint (assuming it has one) accepts API connections from any source IP by default — there is no network-layer allowlist gating who can even attempt to authenticate to the Kubernetes API server. This removes an important defense-in-depth layer: even if IAM/RBAC is well configured, the API server is directly reachable by every host on the internet, widening the surface for credential attacks, exploitation of API-server bugs, and reconnaissance. Enabling authorized networks — even loosely scoped — is a low-cost control that meaningfully reduces exposure.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` matching on the key `master_authorized_networks_config`:
- **PASS** — the `master_authorized_networks_config` block is present (any value/configuration counts, including an empty block, which still signals the feature is enabled).
- **FAIL** — the block is absent entirely.

Note this check only verifies the *feature is turned on*; it does not check what CIDRs are inside it — that overly-broad-CIDR condition (`0.0.0.0/0`) is separately covered by CKV_GCP_18.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"
  # no master_authorized_networks_config block at all -> FAILS
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "corp-network"
    }
  }
}
```

## Remediation steps
1. Add a `master_authorized_networks_config` block to every `google_container_cluster`.
2. Populate it with `cidr_blocks` entries scoped to your CI/CD, VPN, or admin network ranges (never `0.0.0.0/0` — see CKV_GCP_18).
3. If using GKE Autopilot or a fully private cluster, this is still applicable and recommended alongside `private_cluster_config` (CKV_GCP_25).
4. Applying this can briefly interrupt `kubectl` access for anyone connecting from an IP not yet in the allowlist — update the CIDR list and confirm access from your CI/CD pipeline's egress IP before rolling out to production.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEMasterAuthorizedNetworksEnabled.py
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks
