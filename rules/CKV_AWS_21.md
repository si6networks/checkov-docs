# CKV_AWS_21: Ensure all data stored in the S3 bucket have versioning enabled
## Severity
**LOW** (score: 2.0/10)

Without versioning enabled, an S3 bucket cannot recover objects that are accidentally deleted or overwritten (including via compromised credentials), an availability/integrity gap rather than a direct confidentiality exposure.

## Summary
Ensures S3 buckets have versioning enabled so that overwritten or deleted objects can be recovered from prior versions.

## Applicability
- **CloudFormation**: `AWS::S3::Bucket` — inspects `Properties/VersioningConfiguration/Status`, expecting `Enabled`.
- **Terraform** (graph-based check): `aws_s3_bucket` (legacy inline `versioning` block) and the separate `aws_s3_bucket_versioning` resource (AWS provider v4+ split resource model), expecting `versioning_configuration.status = "Enabled"`.

## Why it matters
Without versioning, any accidental overwrite, deletion (including via a compromised/misused IAM credential), or malicious action (e.g., ransomware-style encryption of objects, or an attacker covering their tracks by deleting evidence/log data) permanently destroys the prior object content — there is no way to recover it. Versioning matters because:
- It provides a critical recovery mechanism against operator error (a bad deploy script that overwrites production data, an accidental `aws s3 sync --delete`).
- It provides forensic value during incident response: if an attacker modifies or deletes objects (e.g., tampering with audit logs, backups, or artifact repositories stored in S3), prior versions remain retrievable as evidence and for restoration.
- Combined with MFA Delete and S3 Object Lock, versioning is a foundational building block for ransomware-resilient and compliance-grade (e.g., SEC 17a-4, HIPAA) data retention architectures — without it, those additional controls have nothing to build on.

## How Checkov evaluates this
- **CloudFormation** (`BaseResourceValueCheck`): checks `Properties/VersioningConfiguration/Status` equals `Enabled` → PASS; anything else (including `Suspended` or missing) → FAIL.
- **Terraform** (graph check, JSON policy): passes if either:
  - the `aws_s3_bucket.versioning.enabled` attribute is `true` (legacy inline block); OR
  - the bucket has a connected `aws_s3_bucket_versioning` resource whose `versioning_configuration.status` equals `Enabled`.
  It fails if versioning is absent entirely, explicitly disabled, or only `Suspended`.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "artifacts" {
  bucket = "company-build-artifacts"
}

resource "aws_s3_bucket_versioning" "artifacts_versioning" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Suspended"   # FAILS CKV_AWS_21
  }
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "artifacts" {
  bucket = "company-build-artifacts"
}

resource "aws_s3_bucket_versioning" "artifacts_versioning" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"   # fix
  }
}
```

## Remediation steps
1. Add (or update) an `aws_s3_bucket_versioning` resource (AWS provider v4+) pointing at the bucket, with `versioning_configuration.status = "Enabled"` — or set the inline `versioning { enabled = true }` block if using an older provider version.
2. Pair versioning with an S3 Lifecycle rule to expire/transition noncurrent versions after a reasonable retention period, since versioning alone will grow storage costs indefinitely as objects are overwritten.
3. For buckets holding especially critical data (backups, compliance records), also consider enabling MFA Delete and/or S3 Object Lock (note: Object Lock must be enabled at bucket creation time and cannot be added retroactively).
4. Enabling versioning does not retroactively version objects that existed before it was turned on in a special way — it simply means all future writes/deletes get a version; existing objects become "version null" until modified.
5. Once versioning is `Enabled`, it can be `Suspended` but never fully disabled/removed on a bucket — plan the change knowing this is effectively a one-way door.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3Versioning.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketVersioning.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
