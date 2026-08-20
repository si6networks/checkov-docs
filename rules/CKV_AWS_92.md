# CKV_AWS_92: Ensure the ELB has access logging enabled

## Severity
**LOW** (score: 2.0/10)

Missing access logging on a classic ELB removes visibility into request traffic needed for security monitoring and incident response, an availability/detective-control gap rather than a direct exploit path.

## Summary
This check fails when a "classic" Elastic Load Balancer (ELB, i.e. the original ELB generation, not ALB/NLB) does not have access logging enabled.

## Applicability
- **Terraform**: `aws_elb` resource — inspects `access_logs[0].enabled`.
- **CloudFormation**: `AWS::ElasticLoadBalancing::LoadBalancer` resource — inspects `Properties/AccessLoggingPolicy/Enabled`.

## Why it matters
Classic Load Balancers, though a legacy AWS load-balancing offering, are still deployed in older environments and continue to front production traffic in many organizations. As with ALB/NLB, access logs are the primary forensic record of what traffic actually reached the load balancer — client IPs, request timestamps, response codes, and backend latencies. Without logging enabled, a security incident (e.g., a web application attack, credential stuffing campaign, or unusual traffic spike) leaves no audit trail to investigate after the fact, and there is no way to retroactively enable logging for traffic that already occurred. This gap is especially risky for legacy ELBs because they are often less actively monitored than newer ALB/NLB deployments, making log-based detection even more important as a compensating control.

## How Checkov evaluates this
- **Terraform**: `BaseResourceCheck.scan_resource_conf` — if the `access_logs` block is absent → FAILED. If present but the `enabled` key is absent → PASSED (Terraform/AWS default for a present-but-unconfigured block is treated as sufficient here). If `enabled` is present, it must equal `[True]`; otherwise → FAILED.
- **CloudFormation**: `BaseResourceValueCheck` inspects `Properties/AccessLoggingPolicy/Enabled` — no explicit expected value override is set, so it uses the class default, which checks for truthy/`true`. Missing or `false` → FAILED.

## Non-compliant example
```hcl
resource "aws_elb" "classic" {
  name               = "legacy-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
  # no access_logs block
}
```

## Remediated example
```hcl
resource "aws_elb" "classic" {
  name               = "legacy-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  access_logs {
    bucket        = aws_s3_bucket.elb_logs.id
    bucket_prefix = "legacy-elb"
    interval      = 60
    enabled       = true
  }
}
```

## Remediation steps
1. Add an `access_logs` block (Terraform) or `AccessLoggingPolicy` (CloudFormation) with `enabled = true`.
2. Ensure the target S3 bucket has a policy granting the AWS ELB service account in your region `s3:PutObject` permission — classic ELB uses a different (region-specific) log delivery account than ALB/NLB.
3. Consider migrating from Classic ELB to an Application or Network Load Balancer — Classic ELB is a legacy product with fewer features and AWS recommends migrating for new and existing workloads.
4. Set an S3 lifecycle rule to expire/transition old log objects to control cost.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBAccessLogs.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ELBAccessLogs.py
- AWS docs: https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html
