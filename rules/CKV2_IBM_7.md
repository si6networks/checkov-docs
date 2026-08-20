# CKV2_IBM_7: Ensure Kubernetes clusters are accessible by using private endpoint and NOT public endpoint

## Severity
**CRITICAL** (score: 9.0/10)

A Kubernetes cluster with a public service endpoint exposes the cluster management/API plane to the internet, a classic and heavily-exploited path to full cluster compromise if credentials or vulnerabilities are found.

## Summary
This check ensures that an IBM Cloud Kubernetes Service cluster (`ibm_container_cluster`) has its private service endpoint enabled (`private_service_endpoint = true`) and its public service endpoint disabled or absent, so the cluster's Kubernetes master/API server is reachable only over private connectivity.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ibm_container_cluster`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating attributes of the cluster resource.

## Why it matters
The Kubernetes API server is the control-plane endpoint that can be used to create/modify/delete workloads, read secrets, and manage cluster-wide RBAC — full compromise of the API server generally means full compromise of the cluster. If the cluster's public service endpoint is enabled, the API server is reachable from the internet, meaning it becomes a target for credential-stuffing against `kubectl` authentication, exploitation of any Kubernetes API vulnerabilities, and reconnaissance/scanning by automated bots that specifically look for exposed Kubernetes API servers. Restricting access to the private service endpoint only means the API server can be reached solely via the private network (VPC, VPN, Direct Link), which removes it from public internet-facing exposure entirely and forces attackers to first gain a foothold on the private network before they can even attempt to reach the control plane.

## How Checkov evaluates this
The check requires all of the following:
1. `private_service_endpoint` attribute **exists** on `ibm_container_cluster`.
2. `private_service_endpoint` equals (case-insensitively) `"True"`.
3. Either `public_service_endpoint` does **not exist**, OR it exists but is **not** (case-insensitively) equal to `"True"`.

The check **fails** if the private endpoint is not enabled, or if the public endpoint is explicitly enabled (`true`) alongside it.

## Non-compliant example
```hcl
resource "ibm_container_cluster" "cluster" {
  name              = "prod-cluster"
  datacenter        = "dal10"
  default_pool_size = 3
  machine_type      = "b3c.4x16"
  hardware          = "shared"

  public_service_endpoint  = true
  private_service_endpoint = false
}
```

## Remediated example
```hcl
resource "ibm_container_cluster" "cluster" {
  name              = "prod-cluster"
  datacenter        = "dal10"
  default_pool_size = 3
  machine_type      = "b3c.4x16"
  hardware          = "shared"

  public_service_endpoint  = false
  private_service_endpoint = true
}
```

## Remediation steps
1. Set `private_service_endpoint = true` on the `ibm_container_cluster` resource.
2. Set `public_service_endpoint = false`, or remove the attribute entirely so it defaults to disabled.
3. Ensure your CI/CD systems, `kubectl` clients, and admin workstations have private network connectivity to the cluster (VPN, Direct Link, or a bastion/jump host inside the same VPC) before disabling the public endpoint, or you will lose the ability to manage the cluster remotely.
4. Note: enabling/disabling the public endpoint after cluster creation may require an explicit API call or provider-supported update — verify the provider version supports in-place toggling, since some configurations require cluster recreation.
5. Combine with restricting the cluster's Calico/network policies and IBM Cloud IAM access policies for defense in depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_K8sClustersAccessibleViaPrivateEndPt.json
- IBM Cloud docs: https://cloud.ibm.com/docs/containers?topic=containers-plan_clusters#private_only
