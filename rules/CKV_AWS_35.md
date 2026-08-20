# CKV_AWS_35: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
## Severity
**LOW** (score: 2.0/10)

CloudTrail logs are a sensitive audit trail of account activity; encrypting them with a customer-managed KMS key (instead of only default SSE-S3) ensures the organization controls who can decrypt and access that forensic record, which matters if the logs are ever needed to investigate a breach.

## Summary
Requires AWS CloudTrail trails to encrypt their delivered log files at rest using a customer-managed KMS key, rather than relying only on default Amazon S3-managed (SSE-S3) encryption.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks**: CloudFormation, Terraform
- **Resource types**: `AWS::CloudTrail::Trail` (CloudFormation), `aws_cloudtrail` (Terraform)

## Why it matters
CloudTrail logs are the authoritative record of API activity across your AWS account — every `AssumeRole`, `console login`, IAM change, data-plane S3 access (if enabled), and resource modification. This makes CloudTrail logs simultaneously your most important forensic/audit asset and a high-value target for an attacker trying to cover their tracks or learn about your environment (e.g., discovering role names, resource ARNs, and access patterns to plan further attacks). Without a customer-managed KMS key, the log files are encrypted with the default SSE-S3 mechanism, which gives you no control over who can decrypt the logs, no independent audit trail of decrypt operations, no ability to segregate access by principal via a key policy, and no way to instantly and cryptographically revoke access to historical logs during an incident. A CMK lets you enforce a tightly scoped key policy (e.g., only your security/SOC team's role can decrypt), get CloudTrail-level visibility (via the key's own CloudTrail-recorded usage) into exactly who reads audit logs, and rotate/retire the key independently of the S3 bucket lifecycle.

## How Checkov evaluates this
Both implementations are simple value checks using the `ANY_VALUE` sentinel:
- **Terraform** (`aws_cloudtrail`): inspects the `kms_key_id` attribute — **PASS** if any non-empty value is set; **FAIL** if absent/empty.
- **CloudFormation** (`AWS::CloudTrail::Trail`): inspects `Properties.KMSKeyId` — **PASS** if any non-empty value is set; **FAIL** if absent/empty.

## Non-compliant example
```hcl
resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  # kms_key_id omitted -> relies on default SSE-S3 encryption only
}
```

```yaml
Resources:
  OrgTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: org-trail
      S3BucketName: !Ref CloudTrailBucket
      IsMultiRegionTrail: true
      IncludeGlobalServiceEvents: true
      # KMSKeyId not specified
```

## Remediated example
```hcl
resource "aws_kms_key" "cloudtrail" {
  description             = "CMK for CloudTrail log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn   # customer-managed key
}
```

```yaml
Resources:
  OrgTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: org-trail
      S3BucketName: !Ref CloudTrailBucket
      IsMultiRegionTrail: true
      IncludeGlobalServiceEvents: true
      KMSKeyId: !GetAtt CloudTrailKmsKey.Arn
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to CloudTrail, with a key policy that grants the CloudTrail service (`cloudtrail.amazonaws.com`) `kms:GenerateDataKey*` and `kms:DescribeKey`, and grants your security team's principals `kms:Decrypt`.
2. Set `kms_key_id` (Terraform) or `KMSKeyId` (CloudFormation) on the trail to the CMK's ARN.
3. Enable automatic key rotation on the CMK.
4. Applying a KMS key to an existing trail is an in-place `UpdateTrail` API call — it re-encrypts newly delivered logs going forward; it does not retroactively re-encrypt historical log files already written under SSE-S3.
5. If you use CloudTrail Lake or multiple trails/organization trails, apply the same CMK requirement consistently across all of them.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailEncryptionWithCMK.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudtrailEncryption.py
- AWS docs: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
