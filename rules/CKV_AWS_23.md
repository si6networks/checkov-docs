# CKV_AWS_23: Ensure every security group and rule has a description

## Severity
**LOW** (score: 2.0/10)

Missing rule descriptions is a governance/hygiene gap that hampers later auditing of security group rules but creates no exploitable exposure by itself.

## Summary
This check ensures that every security group and every individual security group rule (ingress/egress) includes a non-empty `description`, so the intent of each rule is documented directly in the configuration.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:**
  - CloudFormation: `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`, `AWS::EC2::SecurityGroupEgress`
  - Terraform: `aws_security_group`, `aws_security_group_rule`, `aws_db_security_group`, `aws_elasticache_security_group`, `aws_redshift_security_group`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`

## Why it matters
Security groups are the primary network access-control mechanism for most AWS resources, and they tend to accumulate rules over time as different engineers add exceptions for new services, ports, or IP ranges. Without a description on each rule, it becomes very difficult during an audit or incident response to determine *why* a given rule exists, whether it is still needed, or whether it is safe to remove — leading to "rule graveyards" where nobody wants to delete an old, possibly-overly-permissive rule for fear of breaking something unknown. This directly undermines least-privilege reviews and increases the time to detect and remediate an overly broad or stale rule (e.g. a temporary port opened for a debugging session that was never a documented, time-boxed exception). Mandating descriptions is a governance control that makes security group hygiene auditable and makes it far easier to spot and challenge rules that shouldn't exist.

## How Checkov evaluates this
**CloudFormation** (`SecurityGroupRuleDescription.py`):
- For `AWS::EC2::SecurityGroup`: examines the `Properties.SecurityGroupIngress` and `Properties.SecurityGroupEgress` lists. If any rule object is missing a `Description` key or has an empty one, the check **FAILS**. If all inline rules have non-empty descriptions (or there are none), it **PASSES**.
- For `AWS::EC2::SecurityGroupIngress`/`AWS::EC2::SecurityGroupEgress` (standalone rule resources): **PASSES** only if `Properties.Description` is present and non-empty; otherwise **FAILS**.

**Terraform** (`SecurityGroupRuleDescription.py`):
- Checks the resource's own top-level `description` attribute.
- For `aws_security_group` resources (no `type` attribute present), it additionally inspects every inline `ingress` and `egress` block; each block must itself have a non-empty `description`.
- For `aws_security_group_rule` (has a `type` attribute of `ingress`/`egress`), only the resource-level `description` is checked.
- **FAILS** if the group-level description is missing/empty, or if any inline ingress/egress block lacks a description. **PASSES** only when every applicable description is present and non-empty.

## Non-compliant example
```hcl
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Allows public HTTPS access to the web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Public HTTPS access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediation steps
1. Add a `description` attribute to the security group resource itself, summarizing the group's overall purpose.
2. Add a `description` attribute to every `ingress`/`egress` block (or standalone `aws_security_group_rule`/CloudFormation ingress-egress resource), explaining the specific reason for that rule (e.g. "Allow HTTPS from CloudFront", "Allow DB access from app tier").
3. For CloudFormation, add `Description` under `Properties` on the SG resource and within each entry of `SecurityGroupIngress`/`SecurityGroupEgress`.
4. Treat this as an opportunity to review whether each rule is still needed — a rule you cannot meaningfully describe is a good candidate for removal.
5. Adding a description to an existing rule is a metadata-only update in AWS and does not require resource replacement or downtime.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupRuleDescription.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SecurityGroupRuleDescription.py)
- [AWS Security Groups documentation](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
