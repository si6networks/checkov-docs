# CKV2_AWS_1: Ensure that all NACL are attached to subnets

## Severity
**MEDIUM** (score: 4.5/10)

Subnets without an attached NACL lose an extra layer of stateless network filtering, weakening defense-in-depth for network segmentation even though security groups may still provide primary access control.

## Summary
This check ensures that every Network ACL (NACL) defined in Terraform is actually attached to at least one subnet, either directly or through its parent VPC's default association.

## Applicability
Terraform (AWS provider). Applies to `aws_network_acl` resources, evaluated in connection with `aws_subnet` and `aws_vpc` resources.

## Why it matters
A Network ACL that is defined but never attached to a subnet provides zero actual protection — it's dead configuration that gives a false sense of security during review ("we have a NACL restricting traffic X") while the subnet in question is actually governed only by the VPC's default (permit-all) NACL or security groups alone. This is a "config drift" / defense-in-depth gap: reviewers and auditors may believe network-layer filtering is enforced when it is not, and the associated subnet's resources rely solely on security groups for isolation. In stricter compliance environments, unassociated NACLs are itself a signal of incomplete or abandoned IaC.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_network_acl` resources and passes if either of two connection patterns is satisfied:
1. The `aws_network_acl` and an `aws_subnet` are both connected to the same `aws_vpc` (implying the NACL is the VPC's association target), **or**
2. The `aws_network_acl` is directly connected to an `aws_subnet` **and** it has a `subnet_ids` attribute set (i.e., subnets are explicitly listed on the NACL resource).

If neither condition holds — i.e., the NACL exists but has no `subnet_ids` and no resolvable connection to any subnet — the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_network_acl" "app_nacl" {
  vpc_id = aws_vpc.main.id
  # No subnet_ids and no aws_network_acl_association referencing aws_subnet.app
}
```

## Remediated example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_network_acl" "app_nacl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.app.id]   # <-- fixed: NACL explicitly attached to the subnet

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 443
    to_port    = 443
  }
}
```

## Remediation steps
1. Add `subnet_ids = [...]` directly on the `aws_network_acl` resource, listing every subnet it should govern.
2. Alternatively, use a separate `aws_network_acl_association` resource to attach the NACL to one or more subnets if you manage associations independently.
3. Remove NACL resources that are genuinely unused/leftover from refactors, rather than leaving orphaned network ACLs in the codebase.
4. After apply, verify in the AWS Console (VPC > Network ACLs > Subnet associations) that the intended subnets show the expected NACL, since a subnet always has exactly one NACL association (default or custom) and misconfigurations can silently fall back to the VPC default.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/SubnetHasACL.json
