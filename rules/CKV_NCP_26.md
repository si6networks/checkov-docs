# CKV_NCP_26: Ensure Access Control Group has Access Control Group Rule attached
## Severity
**LOW** (score: 3.0/10)

An Access Control Group without any rule attached is a configuration completeness/hygiene gap rather than a direct exposure, since an ACG with no rules does not itself grant unintended access.

## Summary
This graph-based check ensures that every NCloud `ncloud_access_control_group` resource has at least one `ncloud_access_control_group_rule` connected to it, so the group is not left as an empty, unenforced container.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_access_control_group` (checked for a graph connection to `ncloud_access_control_group_rule`)
- **Check type:** graph-based connection check (JSON policy)

## Why it matters
An Access Control Group (ACG) with no rules attached is either a no-op or, depending on NCP's default behavior, may fall back to a permissive default (allowing all traffic) rather than the intended deny-by-default posture. Defining an ACG without any associated rule resources is a common configuration drift/mistake — for example, the rule resource may have been deleted, renamed, or never created after refactoring — leaving instances attached to that group with unintended network exposure or, conversely, with no legitimate traffic able to reach them (an availability problem). Ensuring the graph connection exists catches both silent security gaps and broken infrastructure-as-code before it is applied.

## How Checkov evaluates this
This is a **graph check** (JSON policy), not a Python-based single-resource check. Its definition:
```json
{
  "and": [
    {"cond_type": "filter", "attribute": "resource_type", "value": ["ncloud_access_control_group"], "operator": "within"},
    {"resource_types": ["ncloud_access_control_group"], "connected_resource_types": ["ncloud_access_control_group_rule"], "operator": "exists", "cond_type": "connection"}
  ]
}
```
- It first filters the resource graph down to `ncloud_access_control_group` resources.
- It then requires that each such resource has at least one graph **connection** to an `ncloud_access_control_group_rule` resource (connections are typically established via Terraform references, e.g., the rule resource pointing to the ACG's ID/number).
- **PASS:** the ACG resource is referenced by (connected to) at least one `ncloud_access_control_group_rule`.
- **FAIL:** the ACG resource has no `ncloud_access_control_group_rule` referencing it anywhere in the configuration.

## Non-compliant example
```hcl
resource "ncloud_access_control_group" "app_acg" {
  name        = "app-acg"
  description = "ACG for application tier"
  vpc_no      = ncloud_vpc.example.vpc_no
}
# No ncloud_access_control_group_rule resource references app_acg anywhere.
```

## Remediated example
```hcl
resource "ncloud_access_control_group" "app_acg" {
  name        = "app-acg"
  description = "ACG for application tier"
  vpc_no      = ncloud_vpc.example.vpc_no
}

resource "ncloud_access_control_group_rule" "app_acg_rule" {
  access_control_group_no = ncloud_access_control_group.app_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "10.0.0.0/16"
    port_range  = "8080"
    description = "Allow internal app traffic"
  }
}
```

## Remediation steps
1. For every `ncloud_access_control_group` resource in your configuration, add at least one `ncloud_access_control_group_rule` that references it via `access_control_group_no`.
2. Explicitly define both inbound and outbound rules as needed rather than relying on implicit/default behavior.
3. If an ACG is intentionally a placeholder for future use, either remove it until rules are ready, or add a minimal, deliberately restrictive rule (e.g., deny-all/no ingress) with a comment explaining the intent.
4. Re-run `terraform plan`/Checkov to confirm the graph connection now resolves correctly after adding the rule resource.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ncp/AccessControlGroupRuleDefine.json)
