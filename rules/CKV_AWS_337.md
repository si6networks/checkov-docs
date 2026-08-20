# CKV_AWS_337: Ensure SSM parameters are using KMS CMK
## Severity
**HIGH** (score: 7.5/10)

SecureString SSM parameters are still encrypted by the AWS-managed KMS key even without a customer-managed CMK, so the gap is weaker key-management control (rotation, access policy, auditing) over parameters that likely hold secrets, rather than an absence of encryption entirely.

## Summary
This check requires that any `aws_ssm_parameter` of type `SecureString` sets `key_id` to a customer-managed KMS key, rather than relying on the AWS-managed default `alias/aws/ssm` key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_ssm_parameter`
- **Scope:** Only parameters with `type = "SecureString"` — `String` and `StringList` parameters are not encrypted and automatically pass this check.

## Why it matters
SSM Parameter Store `SecureString` parameters are frequently used to store application secrets, database credentials, API keys, and other sensitive configuration values. If encrypted with the AWS-managed default key, you lose the ability to define a custom key policy restricting exactly which IAM principals may decrypt the parameter, cannot independently disable/delete the key to revoke all access in an incident, and get less granular CloudTrail visibility into who is decrypting which secrets (all SSM SecureString decrypts using the default key show up against the shared AWS-managed key rather than a key scoped to this specific class of secrets). A CMK lets you enforce least-privilege decrypt access, support key rotation on your own policy, and support cross-account sharing patterns (e.g., a security/secrets-management account) that the default key does not support.

## How Checkov evaluates this
The check (`SSMParameterUsesCMK.py`) is a `BaseResourceValueCheck` with an override:
1. If `type` is not `"SecureString"`, the check **PASSES** immediately (non-secure parameter types aren't KMS-encrypted at all, so the check doesn't apply).
2. Otherwise, it inspects `key_id`. If `key_id` is set to **any** value, the check **PASSES**.
3. If `key_id` is absent (meaning the default AWS-managed `alias/aws/ssm` key is used), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_ssm_parameter" "bad_example" {
  name  = "/app/db_password"
  type  = "SecureString"
  value = var.db_password
  # key_id not set -> encrypted with default AWS-managed key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "ssm_cmk" {
  description         = "CMK for SSM SecureString parameters"
  enable_key_rotation = true
}

resource "aws_ssm_parameter" "good_example" {
  name   = "/app/db_password"
  type   = "SecureString"
  value  = var.db_password
  key_id = aws_kms_key.ssm_cmk.arn
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to application secrets, with a key policy restricting decrypt access to only the specific IAM roles that need to read the parameter (e.g., the application's task/execution role).
2. Set `key_id` on the `aws_ssm_parameter` resource to that key's ARN, key ID, or alias.
3. Grant the consuming principals `kms:Decrypt` on the CMK in addition to `ssm:GetParameter`/`GetParameters` — both permissions are required to actually read a `SecureString` value.
4. Changing `key_id` on an existing parameter re-encrypts the value under the new key in place (no resource replacement required) — but rotate/update any cached values or downstream consumers if they had hardcoded key ARN expectations.
5. Consider using AWS Secrets Manager instead of SSM SecureString for secrets that need automatic rotation; Parameter Store CMK support is appropriate for static or manually-rotated configuration secrets.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SSMParameterUsesCMK.py)
- [AWS: Working with SecureString parameters](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-securestring.html)
