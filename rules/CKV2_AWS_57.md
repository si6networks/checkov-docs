# CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled

## Severity
**LOW** (score: 2.0/10)

Secrets that never rotate remain valid indefinitely, so any credential leaked via logs, code, or a compromised host stays usable by an attacker until someone manually intervenes, meaningfully extending the blast radius and dwell time of a secret-exposure incident.

## Summary
This check requires that every AWS Secrets Manager secret defined in Terraform has an associated `aws_secretsmanager_secret_rotation` resource, ensuring the secret's value is rotated automatically rather than remaining static indefinitely.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_secretsmanager_secret` (the check inspects whether this resource is connected to an `aws_secretsmanager_secret_rotation` resource)

## Why it matters
Secrets that never rotate — database passwords, API keys, service credentials — become higher-value, longer-lived targets. If a secret is ever exposed (leaked in logs, exfiltrated via a compromised CI job, or exposed to an over-privileged IAM principal), the exposure window is unbounded without rotation: the same credential remains valid indefinitely until someone notices and manually rotates it. Automatic rotation via AWS Secrets Manager (typically backed by a Lambda rotation function) bounds the useful lifetime of a leaked credential to the rotation interval, limiting the blast radius of any single compromise and satisfying common compliance requirements (PCI-DSS, SOC 2, NIST 800-53) that mandate periodic credential rotation.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy), not a Python check. Its definition:
1. Filters the graph to nodes of `resource_type` `aws_secretsmanager_secret`.
2. Requires a graph **connection** to exist from that `aws_secretsmanager_secret` resource to a resource of type `aws_secretsmanager_secret_rotation`.

If no `aws_secretsmanager_secret_rotation` resource references the secret (via its `secret_id`), the check **FAILS**. If such a connection exists anywhere in the configuration, it **PASSES**. It does not inspect the rotation schedule's specific values (e.g., `automatically_after_days`) — only that a rotation resource is wired to the secret.

## Non-compliant example
```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/db/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({ password = var.db_password })
}
# No aws_secretsmanager_secret_rotation resource defined -> FAILS
```

## Remediated example
```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/db/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({ password = var.db_password })
}

# Added: rotation configuration wired to the secret -> PASSES
resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    automatically_after_days = 30
  }
}
```

## Remediation steps
1. Deploy (or use AWS's provided SAR template for) a rotation Lambda appropriate for the secret's type (RDS, DocumentDB, Redshift, or a custom rotation function for generic secrets).
2. Add an `aws_secretsmanager_secret_rotation` resource with `secret_id` referencing the secret and `rotation_lambda_arn` pointing to the rotation function.
3. Set `rotation_rules.automatically_after_days` (or `schedule_expression` on newer provider versions) to an interval consistent with your compliance policy (commonly 30–90 days).
4. Grant the rotation Lambda the IAM permissions and network access (VPC/security group) it needs to reach the target data store and Secrets Manager.
5. Test rotation manually once (`aws secretsmanager rotate-secret`) before relying on the schedule, since a broken rotation Lambda can lock out the secret.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/SecretsAreRotated.json
- AWS docs: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets.html
