# CKV_GCP_18: Ensure GKE Control Plane is not public
## Severity
**CRITICAL** (score: 9.0/10)

Allowing 0.0.0.0/0 to reach the GKE control plane API server exposes the cluster's administrative management interface to the entire internet, a direct path to cluster compromise if credentials or vulnerabilities are exploited.

## Summary
This check fails when a `google_container_cluster`'s master-authorized-networks configuration allows `0.0.0.0/0` as an authorized CIDR block, meaning the Kubernetes control-plane API endpoint is reachable from anywhere on the internet.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
The GKE control plane (the Kubernetes API server) is the single most privileged interface into a cluster — anyone who can reach it and authenticate can create/modify workloads, read secrets, and pivot into the cluster's workloads and any connected cloud resources via workload identity or service-account credentials. Even with authentication required, exposing the API server to `0.0.0.0/0` maximizes the attack surface: it's exposed to credential-stuffing/brute-force attempts, exploitation of any future Kubernetes API/authn vulnerability, and DoS. Restricting authorized networks to known corporate/VPN CIDR ranges (defense in depth alongside IAM/RBAC) dramatically reduces who can even attempt to talk to the API server.

## How Checkov evaluates this
The check inspects `master_authorized_networks_config[0].cidr_blocks`:
- **FAIL** — any `cidr_block` value equals `0.0.0.0/0`.
- **PASS** — the `master_authorized_networks_config` block is absent, has no matching `0.0.0.0/0` entry, or all `cidr_blocks` are scoped ranges.

Note this check only looks for the literal `0.0.0.0/0` entry — it does not itself require `master_authorized_networks_config` to be present (that's covered separately by CKV_GCP_20).

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "all"
    }
  }
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
      display_name = "corp-vpn"
    }
    cidr_blocks {
      cidr_block   = "10.0.0.0/16"
      display_name = "internal-jump-hosts"
    }
  }
}
```

## Remediation steps
1. Remove any `cidr_block = "0.0.0.0/0"` entry from `master_authorized_networks_config.cidr_blocks`.
2. Replace it with the specific CIDR ranges of your CI/CD runners, VPN gateway, bastion hosts, or corporate egress IPs that legitimately need `kubectl` access.
3. For maximum protection, combine with `private_cluster_config` (see CKV_GCP_25) so the control plane has no public endpoint at all, only a private one reachable via VPC/VPN/Interconnect.
4. Applying this is generally in-place, but double-check current CI/CD pipeline egress IPs before tightening, to avoid locking out automated deployments.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEPublicControlPlane.py
- GCP docs: https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks
