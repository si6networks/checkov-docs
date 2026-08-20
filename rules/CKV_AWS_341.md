# CKV_AWS_341: Ensure Launch template should not have a metadata response hop limit greater than 1
## Severity
**MEDIUM** (score: 5.0/10)

Allowing an IMDS hop limit greater than 1 lets traffic proxied through the instance (e.g. from a compromised container or reverse proxy) reach the instance metadata service and steal the instance's IAM role credentials via SSRF.

## Summary
Checks that EC2 launch templates and launch configurations restrict the Instance Metadata Service (IMDS) HTTP PUT response hop limit to `1`, preventing metadata responses from being relayed off the instance.

## Applicability
- **Framework**: Terraform
- **Resource types**: `aws_launch_configuration`, `aws_launch_template`

## Why it matters
The EC2 Instance Metadata Service (IMDS) exposes sensitive data to anything running on the instance, including temporary IAM credentials for the instance's attached role. The `http_put_response_hop_limit` value controls how many network hops an IMDSv2 token-fetching request/response can traverse (TTL-like behavior). A hop limit greater than 1 allows metadata responses to be forwarded beyond the instance itself — for example, through a container, a proxy, or a compromised process acting as a network relay (this is exactly the pattern used in the well-known Capital One SSRF breach, where a misconfigured WAF proxy was used to reach IMDS and exfiltrate IAM credentials). Keeping the hop limit at 1 ensures metadata requests cannot be forwarded from containers or nested network namespaces on the instance to an external attacker via SSRF, containing the blast radius of an SSRF vulnerability to the instance's own OS.

## How Checkov evaluates this
This is a Terraform resource value check (`BaseResourceValueCheck`) that inspects the attribute path `metadata_options[0].http_put_response_hop_limit`:
- **PASS**: the value is exactly `1`.
- **FAIL**: the value is any other number (e.g. `2` or higher).
- **PASS (missing block)**: if the `metadata_options` block is absent entirely, the check explicitly passes (`missing_block_result=CheckResult.PASSED`) — Checkov assumes the AWS default hop limit (which is `1` for `aws_launch_template`) is safe when unset. Note this differs from checks that require the block to be explicitly present; here an omitted block does not fail.

## Non-compliant example
```hcl
resource "aws_launch_template" "web" {
  name          = "web-lt"
  image_id      = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 3
  }
}
```

## Remediated example
```hcl
resource "aws_launch_template" "web" {
  name          = "web-lt"
  image_id      = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1   # restrict metadata responses to the instance itself
  }
}
```

## Remediation steps
1. Locate every `aws_launch_template` and `aws_launch_configuration` resource in your Terraform code.
2. Add (or correct) the `metadata_options` block so `http_put_response_hop_limit = 1`.
3. While you're in that block, also set `http_tokens = "required"` to enforce IMDSv2 (see the related check CKV_AWS_79) — hop limit alone does not stop unauthenticated IMDSv1 requests.
4. Apply the change — updating `metadata_options` on a launch template creates a new template version; instances launched from an Auto Scaling Group using `$Latest`/`$Default` will pick it up on next scale event or instance refresh, but running instances are unaffected until replaced.
5. If a workload legitimately needs a higher hop limit (e.g. a container network stack that adds an extra hop before reaching IMDS), evaluate whether IMDS access can instead be brokered through a sidecar/proxy pattern rather than raising the hop limit, to avoid widening SSRF exposure.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LaunchTemplateMetadataHop.py
- AWS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
