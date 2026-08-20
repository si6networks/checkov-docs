# CKV2_AWS_12: Ensure the default security group of every VPC restricts all traffic

## Severity
**HIGH** (score: 7.5/10)

An unrestricted default security group can be inadvertently attached to resources, granting broad open network access and increasing the attack surface for lateral movement or external exposure.

## Summary
This check ensures that the default security group automatically created with every AWS VPC is locked down to deny all inbound and outbound traffic, rather than being left with its permissive default rules or additional custom rules attached.

## Applicability
Terraform (AWS provider). Applies to `aws_vpc` resources, evaluated in connection with their `aws_default_security_group`.

## Why it matters
Every VPC comes with an implicitly-created "default" security group. Historically this default group allows all outbound traffic and all inbound traffic from other resources in the same group — and critically, **any resource launched without an explicit security group silently lands in this default group**, inheriting whatever rules it has. If the default group is left open (or has been given custom ingress/egress rules), an accidentally-unsecured resource — e.g. a developer's test EC2 instance launched without specifying a security group — is instantly exposed to lateral movement within the VPC or unrestricted outbound access (useful for data exfiltration or C2 callbacks). Explicitly restricting the default security group to allow nothing is a well-known AWS/CIS hardening best practice: it turns "forgot to set a security group" from an open door into a fail-closed dead end.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_vpc` and requires a connection to an `aws_default_security_group`, then checks that resource does NOT have any of the following: `ingress.to_port`, `ingress.from_port`, `ingress.self`, `ingress.protocol`, `egress.to_port`, `egress.from_port`, `egress.cidr_blocks`, `egress.protocol`. It also requires no connection from the `aws_default_security_group` to any `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, or `aws_vpc_security_group_egress_rule` resource (i.e., no rules attached via separate rule resources either). In short: the default security group must have **zero** ingress and egress rules defined anywhere. If any ingress/egress block (inline or via separate rule resources) exists on the default security group, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = "-1"
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # No ingress or egress blocks: all traffic is denied by default. <-- fixed
  # Launch actual workloads with their own dedicated, purpose-built security groups.
}
```

## Remediation steps
1. Manage the VPC's default security group explicitly with `aws_default_security_group`, and remove all `ingress`/`egress` blocks from it so it allows nothing.
2. Do not attach `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, or `aws_vpc_security_group_egress_rule` resources to the default security group.
3. Create separate, purpose-specific security groups (`aws_security_group`) for each workload/tier, with least-privilege rules, and attach those explicitly to every resource (EC2 instances, RDS, ELB, etc.).
4. Tag or document the default security group as "restricted — do not use" so future engineers don't assume it's safe to leave resources unassigned to a specific group.
5. Note: `aws_default_security_group` in Terraform takes ownership of AWS's implicit default group — removing the resource from state does not delete it from AWS (it can't be deleted), only stops Terraform managing it.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/VPCHasRestrictedSG.json
