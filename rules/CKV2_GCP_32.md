# CKV2_GCP_32: Ensure TPU v2 is private
## Severity
**HIGH** (score: 7.0/10)

Enabling external IPs on a TPU v2 VM exposes an expensive, compute-privileged ML training resource directly to the internet, meaningfully broadening the network attack surface for a host that may process sensitive training data.

## Summary
This check ensures that a TPU v2 VM resource does not expose external (public) IP addresses on its network interfaces.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_tpu_v2_vm`

## Why it matters
Cloud TPU VMs run high-value ML training/inference workloads, typically with direct SSH-style or gRPC-based access for job orchestration, and often hold datasets, model checkpoints, and service-account credentials with broad IAM permissions (given the compute cost/scale associated with TPU projects). Assigning a TPU VM a public IP address exposes its management interfaces directly to the internet, allowing unauthenticated network scanning and exploitation attempts against any exposed service or misconfigured firewall rule. Keeping TPU VMs private (internal-IP-only) forces all access through controlled paths — VPC peering, Cloud NAT for egress, IAP tunneling, or bastion hosts — significantly shrinking the externally reachable attack surface for one of the most expensive and sensitive compute resources in a GCP environment.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_tpu_v2_vm`:
- **PASS** if `network_config.enable_external_ips` is set to `false`.
- **FAIL** if the attribute is absent (default behavior may allow external IPs) or explicitly set to `true`.

## Non-compliant example
```hcl
resource "google_tpu_v2_vm" "tpu" {
  name         = "my-tpu"
  zone         = "us-central1-a"
  runtime_version = "tpu-vm-tf-2.15.0"
  accelerator_type = "v2-8"

  network_config {
    enable_external_ips = true
  }
}
```

## Remediated example
```hcl
resource "google_tpu_v2_vm" "tpu" {
  name             = "my-tpu"
  zone             = "us-central1-a"
  runtime_version  = "tpu-vm-tf-2.15.0"
  accelerator_type = "v2-8"

  network_config {
    enable_external_ips = false
    network              = google_compute_network.vpc.id
    subnetwork           = google_compute_subnetwork.subnet.id
  }
}
```

## Remediation steps
1. Set `network_config.enable_external_ips = false` on the `google_tpu_v2_vm` resource.
2. Ensure the TPU VM's subnet has Private Google Access enabled (if it needs to reach Google APIs) and/or a Cloud NAT gateway configured for outbound internet access (e.g., pip installs).
3. Provide developer access via IAP TCP forwarding, a bastion host in the same VPC, or Cloud Interconnect/VPN, instead of relying on a public IP.
4. This setting is typically applied at TPU VM creation; changing it on an existing TPU may require recreating the resource.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPTpuV2VmPrivateEndpoint.json
- GCP docs: https://cloud.google.com/tpu/docs/networking-vm
