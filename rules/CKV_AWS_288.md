# CKV_AWS_288: Ensure IAM policies does not allow data exfiltration
## Severity
**HIGH** (score: 7.5/10)

IAM policies permitting data exfiltration actions (e.g. unrestricted S3 GetObject, RDS snapshot export) allow sensitive data to be copied out of the environment by any principal holding the policy.

## Summary
This check fails when an IAM policy document grants actions from cloudsplaining's "data exfiltration" category — permissions that would allow a principal to move data out of AWS storage/services in ways that bypass normal controls (e.g., unrestricted S3 object retrieval/sync, snapshot sharing, or KMS decrypt without corresponding least-privilege scoping).

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resources:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`

## Why it matters
Data exfiltration actions are IAM permissions that, combined with a broad `Resource: "*"` scope, allow a principal to extract data at scale from an AWS account — for instance, `s3:GetObject`/`s3:GetObject*` across all buckets, `ec2:CopySnapshot`/`ec2:CreateSnapshot` combined with sharing, `rds:CreateDBSnapshot` plus `rds:ModifyDBSnapshotAttribute` (to share a snapshot to another account), or `kms:Decrypt` without resource-level restriction. These are exactly the permissions an attacker who compromises an over-privileged role or credential would use to stage large-scale data theft (e.g., dumping all objects from every S3 bucket, or exporting database snapshots to an attacker-controlled account). Flagging these at IaC-review time catches "the policy technically works but is far broader than the workload needs" before it becomes an active exfiltration vector.

## How Checkov evaluates this
The check is implemented via `BaseTerraformCloudsplainingResourceIAMCheck`, delegating to cloudsplaining's `PolicyDocument.allows_data_exfiltration_actions` property, which checks the policy's statements against its built-in list of data-exfiltration-capable actions (typically evaluated in combination with wildcard/broad `Resource` scoping). If any matching actions are found, the check **fails**, listing the specific actions; otherwise it **passes**.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "exfiltration-risk"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "kms:Decrypt"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-read-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "arn:aws:s3:::app-data-bucket/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:us-east-1:123456789012:key/app-key-id"
      }
    ]
  })
}
```

## Remediation steps
1. Replace wildcard `Resource: "*"` with specific bucket/key/instance ARNs that the workload actually needs to read.
2. Split broad "read everything" policies into per-resource or per-prefix scoped statements aligned to actual application data flows.
3. Add `Condition` blocks where applicable (e.g., `s3:ResourceAccount`, VPC endpoint conditions, `aws:SourceVpce`) to further restrict where/how the data can be accessed from.
4. For snapshot-related actions (EC2/RDS), ensure any sharing permissions (`ModifyDBSnapshotAttribute`, `ModifySnapshotAttribute`) are separated from routine read/backup roles and gated behind a distinct, tightly monitored role.
5. Enable data-plane logging (S3 access logs/CloudTrail data events, VPC Flow Logs) alongside the IAM tightening so any residual broad access is at least detectable.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMDataExfiltration.py
- cloudsplaining docs: https://cloudsplaining.readthedocs.io/en/latest/glossary/data-exfiltration.html
