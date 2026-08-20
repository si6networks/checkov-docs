# CKV2_AWS_34: AWS SSM Parameter should be Encrypted
## Severity
**LOW** (score: 2.0/10)

Unencrypted SSM parameters can store configuration values, tokens, or credentials in plaintext, so anyone with read access to the parameter (or a backup/snapshot of it) can retrieve sensitive data directly.

## Summary
This check ensures that `aws_ssm_parameter` resources use the `SecureString` type, which stores the parameter value encrypted with a KMS key rather than as plaintext.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_ssm_parameter`
- **Provider scope:** AWS
- **Category / severity (from Checkov metadata):** Encryption, medium

## Why it matters
AWS Systems Manager Parameter Store is a common place to store configuration values, and in practice it very often ends up holding sensitive data — database connection strings, API keys, passwords, and other secrets — because it's the path of least resistance for injecting config into EC2, Lambda, or ECS workloads. A parameter stored as plain `String` (or `StringList`) is stored and retrievable in plaintext by anyone with `ssm:GetParameter` IAM permission on that parameter, with no additional decryption barrier. If IAM policies are ever broader than intended (a common misconfiguration), or if the parameter is inadvertently exposed via logs, CloudTrail data events, or a debugging endpoint, the secret is immediately readable. `SecureString` parameters, by contrast, are encrypted at rest via KMS, and reading the actual (decrypted) value additionally requires `kms:Decrypt` permission on the associated CMK — providing a second, independently controllable authorization boundary and ensuring the raw value is not exposed in Terraform state or API responses unless a caller explicitly requests decryption and has the necessary KMS grant.

## How Checkov evaluates this
This is a graph check (`AWSSSMParameterShouldBeEncrypted.json`). It is a single attribute condition: the `aws_ssm_parameter` resource's `type` attribute must equal `SecureString`. Any parameter with `type = "String"` or `type = "StringList"` fails the check, regardless of whether the value being stored actually contains sensitive data.

## Non-compliant example
```hcl
resource "aws_ssm_parameter" "db_password" {
  name  = "/app/prod/db_password"
  type  = "String"
  value = var.db_password
}
```

## Remediated example
```hcl
resource "aws_ssm_parameter" "db_password" {
  name   = "/app/prod/db_password"
  type   = "SecureString"
  value  = var.db_password
  key_id = aws_kms_key.ssm_key.arn
}
```

## Remediation steps
1. Change `type` from `String`/`StringList` to `SecureString` for any parameter holding sensitive values.
2. Set `key_id` to a customer-managed KMS key (recommended for auditability and fine-grained key policy control) rather than relying on the AWS-managed `alias/aws/ssm` default key, especially where you need to restrict decrypt access more tightly than the account-wide default key policy allows.
3. Update IAM policies for consumers of the parameter to include `kms:Decrypt` on the associated key, in addition to `ssm:GetParameter`/`ssm:GetParameters` with `WithDecryption = true`.
4. Be aware that Terraform state itself will contain the decrypted value if you pass it via `value` and read it back — ensure Terraform state is itself encrypted and access-restricted (e.g., encrypted S3 backend with strict bucket policies) regardless of this fix.
5. Note: `StringList` type is not supported by `SecureString` in AWS SSM directly; if you need an encrypted list, store it as a single `SecureString` with a delimited format, or use AWS Secrets Manager instead, which may be a better fit for pure secret storage (automatic rotation, resource policies).
6. No resource replacement needed for the type change itself, but any application code performing `GetParameter` calls must add `WithDecryption: true` or it will receive the ciphertext blob instead of the plaintext value.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AWSSSMParameterShouldBeEncrypted.json)
- [AWS Systems Manager Parameter Store documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
