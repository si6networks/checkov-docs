# CKV_NCP_19: Ensure Naver Kubernetes Service public endpoint disabled

## Severity
**CRITICAL** (score: 9.0/10)

Leaving the Naver Kubernetes Service public endpoint enabled exposes the Kubernetes API server -- a full cluster-administrative interface -- directly to the internet, a prime target for unauthorized cluster takeover.

## Summary
This check ensures that a Naver Kubernetes Service (NKS) cluster (`ncloud_nks_cluster`) does not have its control-plane API server exposed via a public network endpoint (`public_network` attribute set to `true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_nks_cluster`
- **Check type:** resource-configuration check (Python, `BaseResourceNegativeValueCheck`)

## Why it matters
The Kubernetes API server is the control plane for the entire cluster: it authenticates and authorizes every `kubectl` command, every `kubelet` interaction, and every controller/operator action. If the API server's endpoint is reachable from the public internet, it becomes a direct target for credential-stuffing against any exposed authentication mechanism, exploitation of unpatched Kubernetes API vulnerabilities, and reconnaissance scanning — all without needing any foothold inside the cloud provider's network first. A publicly reachable control plane significantly widens the attack surface for what is effectively "root" access to the entire cluster, including secrets, workloads, and node-level operations reachable through the Kubernetes API. Keeping `public_network` disabled forces API access through the private network (VPC-internal access, peering, or VPN), so only clients already inside the trusted network boundary can even attempt to authenticate.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`, which fails when the inspected key matches one of the "forbidden" values. It inspects the `public_network` attribute of `ncloud_nks_cluster`, with `True` as the single forbidden value:
- If `public_network = true`, the check **FAILS**.
- If `public_network` is `false` or unset (not matching the forbidden value), the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_nks_cluster" "prod_cluster" {
  name            = "prod-cluster"
  k8s_version     = "1.27.3-nks.1"
  vpc_no          = ncloud_vpc.main.vpc_no
  subnet_no_list  = [ncloud_subnet.k8s.id]
  public_network  = true
}
```

## Remediated example
```hcl
resource "ncloud_nks_cluster" "prod_cluster" {
  name            = "prod-cluster"
  k8s_version     = "1.27.3-nks.1"
  vpc_no          = ncloud_vpc.main.vpc_no
  subnet_no_list  = [ncloud_subnet.k8s.id]
  public_network  = false
}
```

## Remediation steps
1. Set `public_network = false` (or remove the attribute if `false` is the provider default) on every `ncloud_nks_cluster` resource.
2. Ensure `kubectl`/CI-CD pipelines that manage the cluster can reach the private API endpoint — typically via a bastion host, VPN gateway, or by running from within the same VPC/peered network.
3. If temporary public access is unavoidable (e.g. for a specific integration), scope it as narrowly and briefly as possible and prefer NCP-provided IP allow-listing on top of it rather than leaving the control plane openly public.
4. Note that toggling `public_network` on an existing cluster may require the provider to update networking configuration on the control plane — validate in a non-production cluster first.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NKSPublicAccess.py)
- [Naver Cloud Terraform provider: ncloud_nks_cluster](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/nks_cluster)
