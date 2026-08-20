# CKV2_IBM_2: Ensure VPC classic access is disabled

## Severity
**HIGH** (score: 7.5/10)

Classic access on a VPC bridges it to the flatter, less-segmented IBM Cloud Classic network, weakening network isolation and increasing lateral-movement risk without being an immediate direct exposure.

## Summary
This check ensures that an IBM Cloud VPC (`ibm_is_vpc`) does not have classic infrastructure access enabled, i.e., `classic_access` is absent or explicitly set to `false`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ibm_is_vpc`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating a single attribute of the VPC resource.

## Why it matters
IBM Cloud's "classic access" feature allows a Gen 2 VPC to directly communicate with IBM Cloud's older classic infrastructure network. This bridges two networks with different security postures and management boundaries: classic infrastructure historically has fewer of the granular network isolation controls (like security groups scoped per-VPC and network ACLs) that the newer VPC model provides. Enabling classic access effectively extends your VPC's trust boundary into the classic network, increasing the attack surface — a compromise or misconfiguration on the classic side can more easily reach VPC-hosted workloads, and vice versa. Only one VPC per region/account can have classic access enabled at all, so enabling it is a deliberate, high-impact decision that should not happen by accident via unreviewed IaC.

## How Checkov evaluates this
The check passes if either:
1. The `classic_access` attribute does not exist on the `ibm_is_vpc` resource (default/unset), OR
2. The attribute exists and is set (case-insensitively) to `"false"`.

The check **fails** only when `classic_access` is explicitly set to `true`.

## Non-compliant example
```hcl
resource "ibm_is_vpc" "example" {
  name           = "example-vpc"
  classic_access = true
}
```

## Remediated example
```hcl
resource "ibm_is_vpc" "example" {
  name           = "example-vpc"
  classic_access = false
}
```

## Remediation steps
1. Remove the `classic_access` attribute, or explicitly set it to `false`.
2. If classic access is genuinely required (e.g., during a migration from classic infrastructure to VPC), scope and time-box it, and document the business justification and compensating controls (network ACLs, security groups) used to mitigate the expanded trust boundary.
3. Note that only one VPC per region can have classic access enabled — verify no unintended conflicts if this was previously enabled elsewhere.
4. This attribute typically cannot be changed after VPC creation without recreating the VPC — plan accordingly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_VPCclassicAccessIsDisabled.json
- IBM Cloud docs: https://cloud.ibm.com/docs/vpc?topic=vpc-classic-vpc-planning
