# CKV_AWS_79: Ensure Instance Metadata Service Version 1 is not enabled
## Severity
**HIGH** (score: 7.5/10)

Allowing IMDSv1 (instead of enforcing IMDSv2 with token-based session auth) leaves EC2 instances vulnerable to SSRF-based credential theft from the instance metadata service, a well-known real-world attack path to full instance/role compromise.

## Summary
This check fails when an EC2 instance, launch template, or launch configuration allows the legacy, unauthenticated Instance Metadata Service v1 (IMDSv1) rather than requiring the session-token-based IMDSv2.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::EC2::LaunchTemplate` (CloudFormation), `aws_instance`, `aws_launch_configuration`, `aws_launch_template` (Terraform)
- **Check type:** resource

## Why it matters
IMDSv1 answers metadata requests (including temporary IAM role credentials) over plain HTTP with no session/authentication requirement — any process on the instance, or any request an application is tricked into making on the instance's behalf, can retrieve the instance's IAM credentials, user-data (which sometimes contains secrets or bootstrap tokens), and other metadata. This is the exact mechanism exploited in real-world **Server-Side Request Forgery (SSRF)** attacks against cloud-hosted applications: an attacker who can get the application server to make an arbitrary outbound HTTP request (e.g., via an unvalidated URL parameter, a webhook feature, or an XML/PDF parser fetching external resources) can request `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` and steal the instance's IAM role credentials — as happened in the widely-cited 2019 Capital One breach. IMDSv2 mitigates this by requiring a `PUT`-based session token with a hop-limit header, which most SSRF vectors cannot forge (since SSRF typically only allows GET-style requests and doesn't traverse the required custom header).

## How Checkov evaluates this
- **Terraform (`IMDSv1Disabled.py`):**
  - Applies to `aws_instance`, `aws_launch_template`, `aws_launch_configuration`.
  - If `metadata_options` is missing or not a dict → **FAIL** (no override of the historically permissive default).
  - If `metadata_options[0].http_endpoint == ["disabled"]` → **PASS** (metadata service entirely disabled, so IMDSv1 can't be reached either).
  - Otherwise, falls through to the base value check on `metadata_options/[0]/http_tokens`, expecting the value `"required"` — this forces IMDSv2 (token required); `"optional"` (which still allows IMDSv1) or absent → **FAIL**.
- **CloudFormation (`IMDSv1Disabled.py`):**
  - Applies to `AWS::EC2::LaunchTemplate`.
  - If `Properties/LaunchTemplateData/MetadataOptions/HttpEndpoint == "disabled"` → **PASS**.
  - Otherwise checks `Properties/LaunchTemplateData/MetadataOptions/HttpTokens` expecting `"required"`; anything else (including absent, defaulting to `"optional"`) → **FAIL**.

## Non-compliant example
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  # metadata_options omitted entirely -> defaults allow IMDSv1
}
```

```yaml
Resources:
  WebLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: web-lt
      LaunchTemplateData:
        ImageId: ami-0123456789abcdef0
        InstanceType: t3.micro
        MetadataOptions:
          HttpTokens: optional
```

## Remediated example
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```

```yaml
Resources:
  WebLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: web-lt
      LaunchTemplateData:
        ImageId: ami-0123456789abcdef0
        InstanceType: t3.micro
        MetadataOptions:
          HttpEndpoint: enabled
          HttpTokens: required
          HttpPutResponseHopLimit: 1
```

## Remediation steps
1. Add a `metadata_options` block (Terraform) or `MetadataOptions` (CloudFormation) to the instance, launch template, or launch configuration.
2. Set `http_tokens = "required"` / `HttpTokens: required` to enforce IMDSv2-only access.
3. Keep `http_put_response_hop_limit` at `1` unless you have containerized workloads (e.g., ECS on EC2) that require metadata proxying through an additional network hop, in which case increase carefully and only as needed.
4. If metadata access is not needed at all by the workload, set `http_endpoint = "disabled"` for maximum protection.
5. For existing running instances, this can be updated via `aws ec2 modify-instance-metadata-options` without replacement; for launch templates/configurations referenced by Auto Scaling Groups, a new launch template version will need to be rolled out to affect new instances (existing instances in the ASG are unaffected until replaced).
6. Ensure any application code or third-party agent SDKs on the instance already support IMDSv2 before enforcing `required` — older SDKs that hardcode legacy metadata calls without token handling will break.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IMDSv1Disabled.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IMDSv1Disabled.py)
- [AWS EC2 IMDSv2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
