# CKV_GCP_61: Enable VPC Flow Logs and Intranode Visibility

## Severity
**LOW** (score: 2.0/10)

Disabling VPC flow logs/intranode visibility on a GKE cluster removes visibility into pod-to-pod and node network traffic, delaying detection of lateral movement or data exfiltration within the cluster network.

## Summary
This check fails when a `google_container_cluster` (GKE cluster) does not have `enable_intranode_visibility` set to `true`, meaning traffic between pods on the same node is not visible to VPC flow logging and network policy enforcement points.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_container_cluster`
- **Check type:** resource value check (Kubernetes category)

## Why it matters
By default, GKE only routes inter-node pod traffic through the VPC fabric where it's visible to VPC Flow Logs; traffic between two pods scheduled on the *same* node is handled internally and bypasses this visibility. `enable_intranode_visibility` forces all pod-to-pod traffic — even same-node traffic — through the standard VPC networking path, making it observable in flow logs. Without this, an attacker who has compromised one pod and is attempting lateral movement to another pod on the same node can potentially evade network-level detection entirely, since that traffic never appears in flow logs or is subject to the same monitoring/network-policy enforcement as inter-node traffic. This is particularly important for compliance regimes requiring complete network traffic visibility and for effective threat-hunting/incident-response within Kubernetes clusters.

## How Checkov evaluates this
The check (`GKEEnableVPCFlowLogs`) is a `BaseResourceValueCheck` that inspects the `enable_intranode_visibility` attribute:
- **PASS** if `enable_intranode_visibility = true`.
- **FAIL** if the attribute is absent or `false`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "app-cluster"
  location = "us-central1"

  initial_node_count = 1
  # enable_intranode_visibility not set — defaults to false
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "app-cluster"
  location = "us-central1"

  initial_node_count          = 1
  enable_intranode_visibility = true
}
```

## Remediation steps
1. Add `enable_intranode_visibility = true` to the `google_container_cluster` resource.
2. Apply via `terraform apply` — this is an in-place update on existing clusters via the GKE API and does not require cluster recreation.
3. Confirm VPC Flow Logs are enabled on the subnet(s) used by the cluster, since intranode visibility only helps if flow logging is actually collecting the traffic it now surfaces.
4. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEEnableVPCFlowLogs.py)
- [GKE: Intranode visibility](https://cloud.google.com/kubernetes-engine/docs/how-to/intranode-visibility)
