# CKV_TC_7: Ensure Tencent Cloud TKE cluster is not assigned a public IP address

## Severity
**CRITICAL** (score: 9.0/10)

A publicly reachable Kubernetes master or worker node exposes the cluster's control-plane API server or kubelet directly to the internet, bypassing the private-network perimeter that normally gates access to these highly privileged management interfaces.

## Summary
This check ensures that Tencent Kubernetes Engine (TKE) cluster master and worker node configurations are not directly reachable from the public internet — neither via an explicitly assigned public IP nor via a non-zero internet outbound bandwidth allocation that implicitly provisions one.

## Applicability
Terraform, resource type `tencentcloud_kubernetes_cluster` (Tencent Cloud provider), specifically the `master_config` and `worker_config` blocks.

## Why it matters
A Kubernetes cluster's control-plane and worker nodes host the API server, kubelet, and container runtime — components that, if directly internet-reachable, become targets for exploitation of Kubernetes-specific vulnerabilities (unauthenticated API access, kubelet API abuse, container escape chains) as well as generic OS/service scanning. Exposing master or worker nodes publicly bypasses the intended network perimeter of a private cluster architecture and can allow attackers to reach the Kubernetes control plane or individual nodes without first compromising a bastion, VPN, or private network path. This check also treats a non-zero `internet_max_bandwidth_out` as risky when `public_ip_assigned` is not explicitly set, because Tencent Cloud provisions a public IP implicitly whenever outbound internet bandwidth is allocated — an easy-to-miss way of accidentally exposing a node.

## How Checkov evaluates this
This is a `BaseResourceCheck` that iterates every block in `master_config` and `worker_config` on a `tencentcloud_kubernetes_cluster`. For each block, it **FAILS** if either:
1. `public_ip_assigned` is explicitly `true`, or
2. `public_ip_assigned` is not set at all AND `internet_max_bandwidth_out` is set to a value greater than `0` (bandwidth allocation implies a public IP is provisioned).

If neither master nor worker configs meet either failing condition, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_kubernetes_cluster" "example" {
  cluster_name = "prod-cluster"
  vpc_id       = tencentcloud_vpc.app_vpc.id

  worker_config {
    availability_zone = "ap-guangzhou-3"
    instance_type     = "S5.MEDIUM4"
    public_ip_assigned = true
  }
}
```

## Remediated example
```hcl
resource "tencentcloud_kubernetes_cluster" "example" {
  cluster_name = "prod-cluster"
  vpc_id       = tencentcloud_vpc.app_vpc.id

  worker_config {
    availability_zone      = "ap-guangzhou-3"
    instance_type          = "S5.MEDIUM4"
    public_ip_assigned     = false   # no public IP on worker nodes
    internet_max_bandwidth_out = 0
  }
}
```

## Remediation steps
1. Set `public_ip_assigned = false` on every `master_config` and `worker_config` block, or remove the attribute entirely.
2. Ensure `internet_max_bandwidth_out` is `0` or unset whenever `public_ip_assigned` is not explicitly `false`, since a non-zero value alone will trigger this check.
3. Route any required external access (e.g. pulling images, external API calls) through a NAT gateway rather than assigning nodes public IPs directly.
4. For cluster administration, access the API server through Tencent Cloud's private/internal endpoint, a bastion host, or a VPN rather than exposing it publicly.
5. If public exposure is genuinely required for a specific node pool, isolate it in its own node group with strict security-group rules and treat it as an explicit, documented exception.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/TKEPublicIpAssigned.py
