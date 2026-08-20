# CKV_AWS_150: Ensure that Load Balancer has deletion protection enabled
## Severity
**LOW** (score: 2.0/10)

Deletion protection guards against accidental or malicious removal of a load balancer, which is primarily an availability concern rather than a confidentiality or access-control exposure.

## Summary
This check verifies that an Application/Network/Gateway Load Balancer (`aws_lb`/`aws_alb`) has `enable_deletion_protection` set to `true`, preventing the load balancer from being deleted without first disabling the flag.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `aws_lb` and `aws_alb` resources (both map to the same underlying AWS `elasticloadbalancingv2` resource).

## Why it matters
An ALB/NLB is often the single entry point for a production application. Accidental deletion — via a mistaken `terraform destroy`, a bad `terraform apply` that recreates the resource, a fat-fingered console action, or a compromised credential running destructive API calls — causes an immediate, hard outage for every client, since DNS records (e.g. Route 53 alias records) pointing at the load balancer stop resolving to a working target. Deletion protection is a lightweight guardrail: AWS rejects the `DeleteLoadBalancer` API call while the flag is set, forcing an explicit, deliberate action (disable protection, then delete) before the resource can be removed. This converts an accidental one-step outage into a two-step, harder-to-trigger-by-mistake action.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting the `enable_deletion_protection` attribute. Passes when it is `true`; fails when `false` or unset (AWS defaults this to `false`).

## Non-compliant example
```hcl
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
}
```

## Remediated example
```hcl
resource "aws_lb" "app" {
  name                       = "app-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  enable_deletion_protection = true # <-- added
}
```

## Remediation steps
1. Add `enable_deletion_protection = true` to every production `aws_lb`/`aws_alb` resource.
2. For non-production/ephemeral environments where the load balancer is intentionally torn down frequently (e.g. per-PR preview environments), it is reasonable to leave this disabled or gate it via a variable (`enable_deletion_protection = var.environment == "production"`).
3. To actually delete a protected load balancer, first set the attribute to `false` (via `terraform apply` or the console/CLI) and apply, then delete it in a follow-up step — never combine both in a single change without review.
4. This setting has no cost or performance impact; it is safe to enable broadly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LBDeletionProtection.py
- AWS docs: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection
