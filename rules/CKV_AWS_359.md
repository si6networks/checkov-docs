# CKV_AWS_359: Neptune DB clusters should have IAM database authentication enabled

## Severity
**LOW** (score: 2.0/10)

Lacking IAM database authentication forces reliance on long-lived, harder-to-rotate database credentials instead of short-lived IAM-signed tokens, weakening credential hygiene and audit trails but not by itself exposing the database.

## Summary
This check ensures that an `aws_neptune_cluster` resource has `iam_database_authentication_enabled` set to `true`, so that database access can be authenticated via IAM credentials rather than relying solely on database-native credentials.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Check type:** resource check
- **Entities:** `aws_neptune_cluster`

## Why it matters
By default, Amazon Neptune clusters authenticate connections using database-internal mechanisms only. Enabling IAM database authentication allows access control, credential rotation, and auditing for database connections to be unified with the rest of your AWS IAM estate: short-lived, auto-rotated IAM-signed tokens replace long-lived database passwords, connections can be scoped with IAM policies (least privilege per role/user), and authentication attempts are recorded in CloudTrail. Without this, teams often fall back to shared static credentials that are harder to rotate, harder to audit, and more likely to leak into code, config files, or CI logs — a common root cause of database compromise.

## How Checkov evaluates this
This is a straightforward attribute check (`BaseResourceValueCheck`) that inspects the `iam_database_authentication_enabled` attribute on the `aws_neptune_cluster` resource block. If it is not set to `true`, the check **FAILS**; if set to `true`, it **PASSES**.

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier                  = "example-neptune"
  engine                               = "neptune"
  backup_retention_period             = 7
  preferred_backup_window              = "07:00-09:00"
  skip_final_snapshot                  = true
  iam_database_authentication_enabled  = false
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier                  = "example-neptune"
  engine                               = "neptune"
  backup_retention_period             = 7
  preferred_backup_window              = "07:00-09:00"
  skip_final_snapshot                  = true
  iam_database_authentication_enabled  = true
}
```

## Remediation steps
1. Set `iam_database_authentication_enabled = true` on the `aws_neptune_cluster` resource.
2. Grant the relevant IAM roles/users `rds-db:connect` permission scoped to the cluster resource ARN and database user.
3. Update application connection logic to use `neptune-sigv4` / IAM auth signing (via the AWS SDK) instead of, or alongside, static credentials.
4. This is a modifiable attribute in most cases but may require a maintenance window depending on cluster engine version — validate in a non-production cluster first.
5. Pair with least-privilege IAM policies scoping which principals may call `rds-db:connect`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneDBClustersIAMDatabaseAuthenticationEnabled.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
