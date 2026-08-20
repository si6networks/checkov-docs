# CKV_AWS_295: Ensure DataSync Location Object Storage doesn't expose secrets
## Severity
**HIGH** (score: 7.5/10)

This check detects a hardcoded secret_key credential embedded directly in the DataSync object storage location resource configuration, which is an exposed-credential finding that can grant direct unauthorized access to the backing storage.

## Summary
This check ensures that an `aws_datasync_location_object_storage` resource does not have a hardcoded `secret_key` (the object storage secret access key) directly embedded in the Terraform configuration.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_datasync_location_object_storage`

## Why it matters
`aws_datasync_location_object_storage` is used to configure AWS DataSync to talk to a self-managed or third-party S3-compatible object storage endpoint, and it accepts an access key / secret key pair for authentication. Hardcoding the `secret_key` directly in Terraform HCL means that credential ends up in plaintext in version control history, in Terraform state files, in CI/CD logs, and in any plan/apply output — all of which are far more widely accessible than a proper secrets store. Anyone who gains read access to the repo (including former employees, compromised CI runners, or a leaked backup) obtains standing credentials to the object storage backend, potentially enabling data exfiltration, tampering, or ransomware-style encryption of the source data DataSync is configured to read/write.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (Python check) with `ANY_VALUE` as the forbidden value. It inspects the `secret_key` attribute:
- **FAIL** if `secret_key` is set to any non-empty value (i.e., a secret is present directly in the resource configuration).
- **PASS** if `secret_key` is absent/empty in the raw configuration (implying the value is sourced from a variable resolved outside of static config, a secrets manager reference, or simply not hardcoded as a literal).

## Non-compliant example
```hcl
resource "aws_datasync_location_object_storage" "example" {
  server_hostname = "objectstore.example.com"
  bucket_name     = "my-bucket"
  access_key      = "AKIAIOSFODNN7EXAMPLE"
  secret_key      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # hardcoded secret -> FAILS
  agent_arns      = [aws_datasync_agent.example.arn]
}
```

## Remediated example
```hcl
resource "aws_datasync_location_object_storage" "example" {
  server_hostname = "objectstore.example.com"
  bucket_name     = "my-bucket"
  access_key      = "AKIAIOSFODNN7EXAMPLE"
  secret_key      = data.aws_secretsmanager_secret_version.datasync_secret.secret_string  # sourced from Secrets Manager
  agent_arns      = [aws_datasync_agent.example.arn]
}

data "aws_secretsmanager_secret_version" "datasync_secret" {
  secret_id = "datasync/object-storage/secret-key"
}
```

## Remediation steps
1. Remove the plaintext `secret_key` value from the Terraform configuration.
2. Store the secret in AWS Secrets Manager (or SSM Parameter Store SecureString) and reference it via a `data` source at apply time, or inject it via an environment variable / `TF_VAR_*` that is never committed to source control.
3. Rotate the exposed secret key immediately if it was ever committed to version control, since git history retains it even after removal.
4. Consider using IAM role-based or STS-based authentication for the object storage endpoint if supported, to eliminate long-lived static secrets entirely.
5. Add `.gitignore` rules and pre-commit secret-scanning (e.g., gitleaks, detect-secrets) to catch future accidental hardcoding.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DatasyncLocationExposesSecrets.py)
