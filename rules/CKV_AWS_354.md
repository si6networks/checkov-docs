# CKV_AWS_354: Ensure RDS Performance Insights are encrypted using KMS CMKs
## Severity
**HIGH** (score: 7.5/10)

Performance Insights data can include captured SQL text and parameter values that may contain sensitive information, so leaving it encrypted only with the AWS-managed default key instead of a customer-managed key weakens control over who can access that potentially sensitive monitoring data.

## Summary
When RDS/Aurora Performance Insights is enabled, requires that it be encrypted using a customer-managed KMS key (`performance_insights_kms_key_id`) rather than the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource types**: `aws_db_instance`, `aws_rds_cluster_instance`

## Why it matters
Performance Insights captures and stores detailed database performance data, including the actual text of top SQL statements executed against the database. For many applications, SQL statements embed sensitive data directly in query predicates (e.g., `WHERE email = 'user@example.com'` or `WHERE ssn = '123-45-6789'`), meaning Performance Insights data can itself be a repository of sensitive information separate from the database's primary storage. If this data is encrypted only with the AWS-managed default key, you lose the ability to enforce a scoped key policy over who may decrypt performance/query data, get no independent CloudTrail record of decrypt operations tied to your own key, and cannot cryptographically revoke access in an incident. Using a CMK closes this gap and is consistent with the same rationale applied to the database's own storage encryption.

## How Checkov evaluates this
Custom logic in `scan_resource_conf`:
- If `performance_insights_enabled` is `true`, the check requires `performance_insights_kms_key_id` to be present and non-empty — if it's missing or empty, the check **FAILS**.
- If `performance_insights_enabled` is `true` and `performance_insights_kms_key_id` **is** set, the check **PASSES**.
- If `performance_insights_enabled` is not `true` (disabled or unset), the check trivially **PASSES** — there's no Performance Insights data to encrypt, so the CMK requirement doesn't apply.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier                   = "app-db"
  engine                       = "postgres"
  instance_class                = "db.r6g.large"
  allocated_storage            = 100
  username                     = "appadmin"
  password                     = var.db_password
  skip_final_snapshot          = true
  performance_insights_enabled = true
  # performance_insights_kms_key_id omitted -> AWS-managed default key used
}
```

## Remediated example
```hcl
resource "aws_kms_key" "pi" {
  description             = "CMK for RDS Performance Insights"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_db_instance" "app_db" {
  identifier                      = "app-db"
  engine                          = "postgres"
  instance_class                  = "db.r6g.large"
  allocated_storage               = 100
  username                        = "appadmin"
  password                        = var.db_password
  skip_final_snapshot             = true
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.pi.arn   # customer-managed key
}
```

## Remediation steps
1. Find all `aws_db_instance`/`aws_rds_cluster_instance` resources with `performance_insights_enabled = true`.
2. Add `performance_insights_kms_key_id` pointing to a customer-managed KMS key.
3. **Important**: the Performance Insights KMS key can only be set when Performance Insights is first enabled — you cannot change the KMS key on an instance where Performance Insights is already enabled without disabling and re-enabling it (which discards existing Performance Insights history), so plan this during initial provisioning or a scheduled maintenance action.
4. Grant the RDS service the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions in the CMK's key policy.
5. Enable automatic key rotation on the CMK for defense in depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSInstancePerfInsightsEncryptionWithCMK.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.Overview.html
