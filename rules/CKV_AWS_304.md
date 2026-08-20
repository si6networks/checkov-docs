# CKV_AWS_304: Ensure Secrets Manager secrets should be rotated within 90 days
## Severity
**HIGH** (score: 7.5/10)

This check verifies Secrets Manager rotation occurs within a 90-day window; long-lived unrotated secrets increase the blast-radius/time-window of eventual credential compromise, but the secret itself remains protected and access-controlled in the interim.

## Summary
This check ensures an `aws_secretsmanager_secret_rotation` resource's rotation configuration results in an effective rotation interval of 90 days or less, whether specified via `automatically_after_days` or a `schedule_expression` (`rate(...)`/`cron(...)`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_secretsmanager_secret_rotation`

## Why it matters
Regularly rotating secrets (database credentials, API keys, tokens) is a fundamental defense against long-lived credential compromise: if a secret leaks via a log file, a compromised CI pipeline, a misconfigured repo, or an insider threat, the window during which that leaked secret remains valid directly determines how long an attacker retains access. A 90-day (or shorter) rotation cadence is a widely recognized baseline (referenced by PCI DSS and various compliance frameworks) that bounds the blast radius of any single credential leak. Secrets configured with no rotation, or rotation intervals far exceeding 90 days, mean that an old, potentially already-leaked credential could remain valid and exploitable for months or years without anyone noticing.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (Python check). It inspects `rotation_rules`:
- If `automatically_after_days` is set: **PASS** if the value is `<= 90`; otherwise **FAIL**.
- Else if `schedule_expression` is set and starts with `rate(...)`: the check parses the numeric value and unit (days/hours/minutes) and **PASS**es only if the interval is `<= 90 days` (or the equivalent in hours/minutes: `<=2160` hours, `<=129600` minutes); otherwise **FAIL**.
- Else if `schedule_expression` starts with `cron(...)`: the check unconditionally returns **PASS** (the code has a `TODO` noting that evaluating cron-based schedules for compliance is not yet implemented — so cron expressions always pass regardless of actual frequency).
- If `rotation_rules` is absent, or neither field is set/matches, the check **FAIL**s.

## Non-compliant example
```hcl
resource "aws_secretsmanager_secret" "db_creds" {
  name = "prod/db/credentials"
}

resource "aws_secretsmanager_secret_rotation" "db_creds" {
  secret_id           = aws_secretsmanager_secret.db_creds.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    automatically_after_days = 180   # exceeds 90 days -> check FAILS
  }
}
```

## Remediated example
```hcl
resource "aws_secretsmanager_secret" "db_creds" {
  name = "prod/db/credentials"
}

resource "aws_secretsmanager_secret_rotation" "db_creds" {
  secret_id           = aws_secretsmanager_secret.db_creds.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    automatically_after_days = 30   # within 90-day threshold
  }
}
```

## Remediation steps
1. Set `rotation_rules.automatically_after_days` to a value `<= 90` (commonly 30 or 60 days for higher-sensitivity secrets).
2. If using `schedule_expression` with a `rate(...)` expression instead, ensure the interval converts to 90 days or fewer (e.g., `rate(30 days)`).
3. Avoid relying on `cron(...)` schedule expressions if you need this specific Checkov check to meaningfully validate frequency — the current check logic always passes cron-based schedules regardless of actual interval, so a `cron(0 0 1 */6 ? *)` (every 6 months) expression would incorrectly pass; use `rate()` or manual review for cron-scheduled secrets.
4. Ensure a working `rotation_lambda_arn` (or AWS-managed rotation for supported services like RDS) is configured and tested — misconfigured rotation Lambdas can silently fail and leave secrets un-rotated despite a compliant schedule.
5. Apply this to all secrets holding live credentials; secrets storing static, non-rotatable values (e.g., long-lived third-party API keys with no rotation API) may need documented exceptions with compensating controls.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecretManagerSecret90days.py)
