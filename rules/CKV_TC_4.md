# CKV_TC_4: Ensure Tencent Cloud CVM instances do not use the default security group

## Severity
**MEDIUM** (score: 6.0/10)

Default security groups are commonly left in a permissive state, so relying on one risks unintentionally broad network access to the instance, though the actual exposure depends on how that default group is configured.

## Summary
This check ensures that Tencent Cloud CVM instances are attached to purpose-built security groups rather than the account/VPC's default security group.

## Applicability
Terraform, resource type `tencentcloud_instance` (Tencent Cloud provider).

## Why it matters
The default security group in a Tencent Cloud VPC is typically shared across every resource that does not have an explicit security group assigned, and its rules are often broad (or get loosened over time as different teams add ad hoc rules to it for convenience) because it has no single owner or clear intended scope. Using the default group for a specific workload means that instance's exposure is governed by rules nobody designed for it specifically, and any rule change made by another team for their own resource silently changes this instance's exposure too. A dedicated security group lets you apply least-privilege network rules scoped precisely to what that instance needs (specific ports, specific source CIDRs/security groups), and makes firewall changes auditable and attributable to the workload they affect.

## How Checkov evaluates this
This is a `BaseResourceCheck` that inspects two possible attributes on a `tencentcloud_instance`: `orderly_security_groups` and `security_groups`. For each security group ID referenced in either list, Checkov checks whether the string `.default.` appears in it (a naming/reference convention Checkov uses to detect a reference to the default security group). If any referenced group ID contains `.default.`, the check **FAILS**. If neither attribute references a default-named group (or the attributes are simply absent), the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_instance" "db" {
  instance_name     = "db-server"
  availability_zone = "ap-guangzhou-3"
  image_id          = "img-9qabwvbn"
  instance_type     = "S5.MEDIUM4"
  security_groups   = [tencentcloud_security_group.default.id]
}

resource "tencentcloud_security_group" "default" {
  name        = "default"
  description = "default security group"
}
```

## Remediated example
```hcl
resource "tencentcloud_instance" "db" {
  instance_name     = "db-server"
  availability_zone = "ap-guangzhou-3"
  image_id          = "img-9qabwvbn"
  instance_type     = "S5.MEDIUM4"
  security_groups   = [tencentcloud_security_group.db_sg.id]
}

resource "tencentcloud_security_group" "db_sg" {
  name        = "db-server-sg"
  description = "Dedicated security group for db-server: allows only MySQL from app tier"
}

resource "tencentcloud_security_group_rule_set" "db_sg_rules" {
  security_group_id = tencentcloud_security_group.db_sg.id
  ingress {
    action      = "ACCEPT"
    cidr_block  = "10.0.1.0/24"
    protocol    = "TCP"
    port        = "3306"
  }
}
```

## Remediation steps
1. Create a dedicated `tencentcloud_security_group` per workload/role (e.g. web tier, app tier, db tier) with narrowly scoped ingress/egress rules.
2. Update the `security_groups` (or `orderly_security_groups`) attribute on the `tencentcloud_instance` to reference the dedicated group instead of the default one.
3. Audit the existing default security group's rules — if it has accumulated broad rules over time, consider tightening it to a safe minimal baseline once all resources have moved to dedicated groups.
4. Repeat this for any other resource types that still reference the default group, since rule changes to the shared default group affect all attached resources simultaneously.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CVMUseDefaultSecurityGroup.py
