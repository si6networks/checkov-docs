# CKV_AWS_75: Ensure Global Accelerator accelerator has flow logs enabled
## Severity
**LOW** (score: 2.0/10)

Missing flow logs on a Global Accelerator reduces the ability to detect anomalous or malicious traffic patterns traversing the accelerator, a monitoring/detection gap rather than a direct exposure.

## Summary
This check fails when an AWS Global Accelerator accelerator does not have flow logs enabled, meaning connection-level network flow data through the accelerator's static anycast IPs is not being captured.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_globalaccelerator_accelerator`
- **Check type:** resource

## Why it matters
AWS Global Accelerator sits at the network edge, routing client traffic over AWS's global network to backend endpoints (ALBs, NLBs, EC2 instances, Elastic IPs). Flow logs record source/destination IP, ports, protocol, and traffic volume for connections passing through the accelerator. Without them, there is no record of which external clients connected through the accelerator's edge, at what volume, or when — a significant blind spot for detecting DDoS attempts, credential-stuffing bursts, port scanning, or unusual geographic access patterns hitting your public-facing infrastructure before it even reaches your VPC-level VPC Flow Logs or WAF logs. Since Global Accelerator is often the very first hop for internet-facing traffic, its logs are frequently the most useful for correlating an external attack's origin with what your application-layer logs show.

## How Checkov evaluates this
The check (`GlobalAcceleratorAcceleratorFlowLogs.py`) extends `BaseResourceValueCheck` and inspects the nested attribute path `attributes/[0]/flow_logs_enabled` on `aws_globalaccelerator_accelerator`. This corresponds to the `attributes { flow_logs_enabled = ... }` nested block in the Terraform resource. The check passes only if `flow_logs_enabled` is explicitly `true` within that block; it fails if the `attributes` block is missing or `flow_logs_enabled` is `false`/unset.

## Non-compliant example
```hcl
resource "aws_globalaccelerator_accelerator" "public_api" {
  name            = "public-api-accelerator"
  ip_address_type = "IPV4"
  enabled         = true
}
```

## Remediated example
```hcl
resource "aws_globalaccelerator_accelerator" "public_api" {
  name            = "public-api-accelerator"
  ip_address_type = "IPV4"
  enabled         = true

  attributes {
    flow_logs_enabled   = true
    flow_logs_s3_bucket = "public-api-accelerator-flow-logs"
    flow_logs_s3_prefix = "flow-logs/"
  }
}
```

## Remediation steps
1. Add an `attributes` block to the `aws_globalaccelerator_accelerator` resource with `flow_logs_enabled = true`.
2. Specify `flow_logs_s3_bucket` (required when enabling) pointing to an S3 bucket you own, and optionally `flow_logs_s3_prefix` to organize logs.
3. Ensure the target S3 bucket policy grants the Global Accelerator service permission to write objects (AWS manages this automatically when configured through the console/API, but verify via `aws globalaccelerator describe-accelerator-attributes` after apply).
4. This is a non-disruptive, additive change — no accelerator replacement or downtime required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GlobalAcceleratorAcceleratorFlowLogs.py)
- [AWS Global Accelerator flow logs](https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html)
