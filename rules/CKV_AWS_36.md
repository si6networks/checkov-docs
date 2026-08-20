# CKV_AWS_36: Ensure CloudTrail log file validation is enabled

## Severity
**LOW** (score: 2.0/10)

Without log file validation an attacker who compromises the CloudTrail S3 bucket can tamper with or delete logs undetected, undermining forensic integrity and compliance evidence though it does not itself grant any new access.

## Summary
This check ensures that CloudTrail trails have log file integrity validation enabled, so that CloudTrail log files are cryptographically signed and any tampering or deletion after delivery to S3 can be detected.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::CloudTrail::Trail` (CloudFormation property `EnableLogFileValidation`), `aws_cloudtrail` (Terraform attribute `enable_log_file_validation`)

## Why it matters
CloudTrail logs are one of the primary sources of truth for incident response and forensic investigation in an AWS account. If an attacker with sufficient S3 permissions gains access to the CloudTrail bucket, they can delete or modify log files to cover their tracks — unless log file validation is enabled. With validation enabled, CloudTrail delivers a periodic digest file containing hashes of all log files delivered in that period, signed with a private key; any modification, deletion, or forgery of a log file is then cryptographically detectable via the `aws cloudtrail validate-logs` CLI command or third-party tooling. Without this, defenders have no reliable way to prove log integrity, weakening audit trails used for compliance (PCI-DSS, HIPAA, SOC 2) and post-incident investigations.

## How Checkov evaluates this
Both implementations are simple attribute-value checks (`BaseResourceValueCheck`):
- **CloudFormation:** inspects `Properties/EnableLogFileValidation` on `AWS::CloudTrail::Trail`. If not explicitly set to a truthy value, the check **FAILS**.
- **Terraform:** inspects `enable_log_file_validation` on `aws_cloudtrail`. If not set to `true`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  is_multi_region_trail         = true
  enable_log_file_validation    = false
}
```

## Remediated example
```hcl
resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

CloudFormation equivalent:
```yaml
Resources:
  OrgTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: org-trail
      S3BucketName: !Ref TrailBucket
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
```

## Remediation steps
1. Set `enable_log_file_validation = true` (Terraform) or `EnableLogFileValidation: true` (CloudFormation) on every CloudTrail trail.
2. After enabling, periodically run `aws cloudtrail validate-logs --trail-arn <arn> --start-time <ts>` (or automate via a Lambda/EventBridge job) to actually verify the digests — enabling the setting alone doesn't validate logs, it only makes validation possible.
3. Ensure the S3 bucket storing CloudTrail logs also has versioning and appropriately restrictive bucket policies, since validation detects tampering but doesn't prevent deletion.
4. No downtime or resource replacement is required — this is a mutable trail property.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailLogValidation.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudtrailLogValidation.py
- AWS docs: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
