# CKV_ALI_10: Ensure OSS bucket has versioning enabled

## Severity
**LOW** (score: 2.0/10)

Without versioning, accidental or malicious overwrite/deletion of objects (including via a subsequently compromised credential) cannot be recovered, an availability/integrity gap rather than a direct confidentiality exposure.

## Summary
This check ensures Alibaba Cloud OSS buckets have versioning explicitly enabled (`versioning.status = "Enabled"`), so that overwritten or deleted objects can be recovered.

## Applicability
Terraform. Applies to the `alicloud_oss_bucket` resource, specifically its `versioning[0].status` attribute.

## Why it matters
Without versioning, an OSS bucket keeps only the current copy of each object — any overwrite (accidental upload, application bug) or delete (accidental API call, compromised credentials, malicious insider, or ransomware-style destructive attack) permanently destroys the prior data with no built-in recovery path. Versioning preserves every prior version of an object, letting you restore the exact previous state after an accidental or malicious modification/deletion. This is particularly important for buckets storing critical data (backups, audit logs, application state, compliance records) where data loss/tampering could have operational, financial, or regulatory consequences, and it is also a common recovery control against ransomware-style attacks that mass-delete or encrypt-in-place object contents.

## How Checkov evaluates this
This is a Python check (`OSSBucketVersioning.py`) extending `BaseResourceValueCheck`. It inspects the key `versioning/[0]/status` on the `alicloud_oss_bucket` resource and expects the value `"Enabled"`. If the `versioning` block is absent, or present with `status` set to `"Suspended"` (or any other value), the check fails.

## Non-compliant example
```hcl
resource "alicloud_oss_bucket" "backups" {
  bucket = "company-backups"
  acl    = "private"
  # no versioning block - defaults to disabled
}
```

## Remediated example
```hcl
resource "alicloud_oss_bucket" "backups" {
  bucket = "company-backups"
  acl    = "private"

  versioning {
    status = "Enabled"
  }
}
```

## Remediation steps
1. Add a `versioning` block to the `alicloud_oss_bucket` resource with `status = "Enabled"`.
2. For buckets where versioning was previously "Suspended," note that re-enabling only affects objects written after the change — objects overwritten while suspended are not retroactively versioned.
3. Combine versioning with a lifecycle rule to expire old noncurrent versions after a reasonable retention period, to control storage cost growth from retained versions.
4. For highly sensitive buckets, also consider enabling bucket policy/RAM restrictions that prevent version deletion (retention lock equivalent), where supported, to protect against an attacker with delete permissions purging all versions.
5. Verify the change with `alicloud_oss_bucket` state in Terraform plan/apply output, and confirm via the Alibaba Cloud console or `aliyun oss` CLI that versioning shows as Enabled.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/OSSBucketVersioning.py
