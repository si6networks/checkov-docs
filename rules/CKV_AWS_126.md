# CKV_AWS_126: Ensure that detailed monitoring is enabled for EC2 instances

## Severity
**MEDIUM** (score: 5.0/10)

Missing detailed EC2 monitoring only reduces metric granularity (5-minute vs 1-minute intervals) and does not by itself expose data, weaken access controls, or create an attack path.

## Summary
This check requires that EC2 instances enable CloudWatch detailed monitoring (1-minute granularity metrics) rather than relying on the default 5-minute basic monitoring interval.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_instance`

## Why it matters
Basic EC2 monitoring only publishes CloudWatch metrics (CPU, network, disk) at 5-minute intervals. During an incident — a runaway process, a memory leak, a sudden traffic spike, or the early stages of a denial-of-service condition — five minutes is a long time to fly blind. Auto Scaling policies, CloudWatch alarms, and automated remediation (e.g., Lambda functions triggered by alarms) that depend on EC2 metrics will react far more slowly with basic monitoring, which can turn a brief spike into an outage or delay detection of resource exhaustion attacks. Detailed monitoring (1-minute intervals) shortens the detection-to-reaction window for both operational and security-relevant anomalies, at the cost of a small additional CloudWatch charge per instance.

## How Checkov evaluates this
The check is a straightforward attribute-value check (`BaseResourceValueCheck`) against the `aws_instance` resource block:
- It inspects the `monitoring` argument.
- **PASS** if `monitoring = true`.
- **FAIL** if `monitoring` is absent or set to `false`.

There is no special-cased exception logic; it is a direct boolean comparison.

## Non-compliant example
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  # monitoring not set -> defaults to false (basic monitoring)
}
```

## Remediated example
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  monitoring    = true   # enables detailed (1-minute) CloudWatch monitoring
}
```

## Remediation steps
1. Add `monitoring = true` to every `aws_instance` resource block.
2. If instances are provisioned via a launch template or Auto Scaling Group instead, set the equivalent `monitoring { enabled = true }` block on `aws_launch_template` (note: Checkov's supported_resources for this specific check is limited to `aws_instance`, so launch-template-only fleets may not be flagged, but should still be fixed for operational reasons).
3. Confirm the added CloudWatch cost is acceptable (detailed monitoring is billed per instance-metric-hour beyond the free basic tier).
4. No resource replacement is required — `monitoring` can be updated in place via `terraform apply`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EC2DetailedMonitoringEnabled.py)
- [AWS: Enable or Disable Detailed Monitoring for Your Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html)
