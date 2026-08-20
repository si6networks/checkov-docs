# CKV_AWS_108: Ensure IAM policies does not allow data exfiltration
## Severity
**LOW** (score: 2.0/10)

This check (via Cloudsplaining) flags IAM policies that permit actions enabling data exfiltration (e.g. copying/sharing snapshots, exporting objects to attacker-controlled destinations), creating a direct path to a data breach.

## Summary
This check uses the `cloudsplaining` policy-analysis engine to ensure IAM policies do not grant broad, unrestricted permissions to actions that can be used to exfiltrate data out of the AWS account (e.g. copying S3 objects out, creating public snapshots, sharing resources cross-account).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_iam_policy_document` data source (analyzed via the underlying compiled policy JSON).
- **CloudFormation**: `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy`, `AWS::IAM::Role`, `AWS::IAM::User` resources containing inline or attached IAM policy documents.

## Why it matters
Cloudsplaining's data-exfiltration action set covers IAM actions such as `s3:GetObject` combined with unrestricted resource scope, `ec2:CreateSnapshot`/`rds:CreateDBSnapshot` combined with sharing actions, `ssm:GetParameter` for secrets, and similar operations that allow reading or copying data out of AWS-managed storage. When a policy grants these actions broadly (`Resource: "*"`, no conditions), any principal that assumes the role or is attached to the policy — including one compromised via SSRF, a vulnerable application, or a leaked credential — can systematically pull data out of S3 buckets, snapshot and exfiltrate database volumes, or read secrets/parameters far beyond what the workload legitimately needs. This class of over-permissioning is a leading root cause in real-world cloud data breaches, where an initially narrow compromise (e.g. a single EC2 instance) escalates into an account-wide data exfiltration event purely because the attached IAM role had unnecessarily broad read/copy/export permissions.

## How Checkov evaluates this
Both implementations delegate to the `cloudsplaining` library's `PolicyDocument.allows_data_exfiltration_actions` analysis:
- Cloudsplaining scans the policy document's statements for known data-exfiltration-capable actions granted without sufficiently restrictive resource/condition scoping.
- If any such actions are found, the check **FAILS** (the offending action list is returned as the finding).
- If no matching actions are found, the check **PASSES**. Unlike CKV_AWS_107, there is no explicit exclusion list here — every action cloudsplaining flags is reported.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "broad_read" {
  statement {
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = ["*"]
  }
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "scoped_read" {
  statement {
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::my-app-bucket",
      "arn:aws:s3:::my-app-bucket/*",
    ]
  }
}
```

## Remediation steps
1. Replace `Resource: "*"` with explicit ARNs for the specific buckets, tables, keys, or instances the workload actually needs to read.
2. For snapshot/export-capable actions (`ec2:CreateSnapshot`, `rds:CreateDBSnapshot`, `rds:CreateDBSnapshotIfNoneExists`, etc.), scope to the specific resource ARNs and consider adding conditions that block cross-account sharing (e.g. deny `ModifyDBSnapshotAttribute`/`ModifySnapshotAttribute` to public/other-account principals) at the SCP or resource-policy level.
3. Apply IAM Access Analyzer's policy generation to derive the minimal actual set of permissions used by the role, and trim to that set.
4. Separate read/export capabilities into distinct, narrowly-attached policies rather than bundling them into general-purpose "app role" policies, so a compromise of one workload doesn't grant broad exfiltration capability.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMDataExfiltration.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMDataExfiltration.py)
- [cloudsplaining project](https://github.com/salesforce/cloudsplaining)
