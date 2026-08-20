# CKV_AWS_91: Ensure the ELBv2 (Application/Network) has access logging enabled

## Severity
**LOW** (score: 2.0/10)

Missing access logging on an ELBv2 removes a source of forensic and detection data for the load balancer's traffic, hampering incident investigation rather than directly enabling a compromise.

## Summary
This check fails when an Application Load Balancer or Network Load Balancer (ELBv2) does not have S3 access logging enabled, meaning connection-level request logs are not being captured.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_lb` and `aws_alb` resources — inspects `access_logs[0].enabled`. Gateway Load Balancers (`load_balancer_type = "gateway"`) are explicitly excluded and return `UNKNOWN` since access logs are not applicable/available for that type.
- **CloudFormation**: `AWS::ElasticLoadBalancingV2::LoadBalancer` resource — inspects the `LoadBalancerAttributes` list for a `Key: access_logs.s3.enabled` entry with `Value: true`.

## Why it matters
Access logs record every request the load balancer processes — client IP, request path, response code, latency, target, TLS cipher, and more. Without them, security teams have no way to reconstruct what happened during an incident (e.g., identifying the source of a web attack, confirming whether a vulnerability was actually exploited, or investigating unusual traffic patterns), and operators lose visibility needed for troubleshooting outages or performance regressions. Since ALBs/NLBs commonly sit at the edge of an application handling all inbound internet traffic, their logs are often the single richest source of evidence for both security investigations and compliance audits (e.g., PCI-DSS logging requirements). Log absence is discovered — usually the hard way — only after an incident, when it is too late to go back and capture the missing data.

## How Checkov evaluates this
- **Terraform**: `BaseResourceValueCheck` inspects `access_logs/0/enabled/0`. If `load_balancer_type` is `"gateway"`, the check short-circuits to `UNKNOWN` (Gateway Load Balancers don't support this attribute the same way). Otherwise it expects `enabled = true` in the `access_logs` block; missing block or `enabled = false` → FAILED.
- **CloudFormation**: Looks through `Properties.LoadBalancerAttributes` (a list of `{Key, Value}` pairs) for the key `access_logs.s3.enabled`. If its value equals boolean/string `true` → PASSED. If the attribute or the whole `LoadBalancerAttributes` block is absent, or the value is not `true` → FAILED.

## Non-compliant example
```hcl
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  # no access_logs block configured
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "lb_logs" {
  bucket = "my-app-alb-access-logs"
}

resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    prefix  = "app-alb"
    enabled = true
  }
}
```

## Remediation steps
1. Create (or designate) an S3 bucket to receive access logs, with a bucket policy granting the ELB service account `s3:PutObject` permission for the region (AWS publishes region-specific log delivery account IDs).
2. Add an `access_logs` block with `enabled = true` and the target `bucket`/`prefix`.
3. For CloudFormation, add a `LoadBalancerAttributes` entry `{ Key: "access_logs.s3.enabled", Value: "true" }` plus `access_logs.s3.bucket`.
4. Gateway Load Balancers are exempt from this specific attribute — use VPC flow logs or GWLB endpoint-level telemetry instead.
5. Set a lifecycle policy on the log bucket to expire old logs and control storage cost.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBv2AccessLogs.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ELBv2AccessLogs.py
- AWS docs: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
