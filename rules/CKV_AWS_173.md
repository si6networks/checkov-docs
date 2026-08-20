# CKV_AWS_173: Check encryption settings for Lambda environmental variable

## Severity
**LOW** (score: 2.0/10)

Lambda environment variables frequently carry API keys, database credentials, or other secrets, and without KMS encryption they are stored and displayed in plaintext to anyone with read access to the function configuration, widening the pool of principals who can view live secrets.

## Summary
This check requires that when a Lambda function defines environment variables, it also specifies a customer-managed KMS key (`kms_key_arn`/`KmsKeyArn`) to encrypt them, rather than relying solely on Lambda's default service-managed encryption.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_lambda_function`
- **CloudFormation**: `AWS::Lambda::Function`, `AWS::Serverless::Function` (SAM)

## Why it matters
Lambda environment variables are a common place to store configuration that includes sensitive values — database connection strings, API keys, feature flags controlling security-relevant behavior, or third-party service credentials — because they're the simplest way to pass config into a function. AWS encrypts environment variables at rest by default using an AWS-managed key, but that default key cannot be scoped with a custom key policy, cannot have its usage independently audited per-application via CloudTrail with fine-grained key permissions, and cannot be rotated or revoked independently of the whole AWS account's default Lambda key usage.

Specifying an explicit customer-managed KMS key lets you control exactly which IAM principals/roles can decrypt the function's environment variables (via the key policy, separate from Lambda's execution role permissions), get a dedicated audit trail of decrypt operations, and revoke access without affecting other functions sharing the AWS-managed default key. Without a CMK, if the Lambda execution role or account is compromised, environment variable secrets are protected only by AWS's own default key management, which is a coarser and less controllable boundary.

## How Checkov evaluates this
**Terraform**: the check inspects the `environment` block and `kms_key_arn` attribute on `aws_lambda_function`.
- If `environment` variables are configured: the check requires `kms_key_arn` to be present and non-empty. If `kms_key_arn` is missing, or set to an empty string (`""`), the check **FAILS**. If it's present and non-empty, it **PASSES**.
- If no `environment` block is configured but `kms_key_arn` **is** set anyway, the check **FAILS** (a KMS key configured with no environment variables to encrypt is flagged as a state mismatch/misconfiguration).
- If neither `environment` nor `kms_key_arn` are set, the result is `UNKNOWN` (nothing to encrypt, no verdict needed).

**CloudFormation**: the check inspects `Properties.Environment.Variables` and `Properties.KmsKeyArn` on `AWS::Lambda::Function` / `AWS::Serverless::Function`. If `Environment.Variables` is present and non-empty but `KmsKeyArn` is not set, the check **FAILS**. If there are no environment variables, or a `KmsKeyArn` is present, the check **PASSES**. If `Environment` is present but not a proper dict/mapping, the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_lambda_function" "api_handler" {
  function_name = "api-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"

  environment {
    variables = {
      DB_PASSWORD = "supersecret"
      API_KEY     = "sk-live-abc123"
    }
  }
  # kms_key_arn not set -> encrypted with AWS-managed default key only
}
```

## Remediated example
```hcl
resource "aws_kms_key" "lambda_env" {
  description = "CMK for Lambda environment variable encryption"
}

resource "aws_lambda_function" "api_handler" {
  function_name = "api-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
  kms_key_arn   = aws_kms_key.lambda_env.arn  # added

  environment {
    variables = {
      DB_PASSWORD = "supersecret"
      API_KEY     = "sk-live-abc123"
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key scoped for Lambda environment variable encryption, with a key policy restricting `kms:Decrypt` to the specific function's execution role.
2. Set `kms_key_arn` (Terraform) / `KmsKeyArn` (CloudFormation/SAM) to that key's ARN on the function resource.
3. Grant the Lambda execution role `kms:Decrypt` (and typically `kms:GenerateDataKey` for encryption during deploys) on the CMK's key policy — without this, function invocations/deploys will fail to resolve environment variables.
4. Prefer moving genuinely sensitive secrets (API keys, DB passwords) out of environment variables entirely and into AWS Secrets Manager or SSM Parameter Store with fine-grained IAM access, using environment variables only for non-sensitive config or references (e.g. a secret's ARN) — this check only ensures encryption-at-rest of the raw environment variable value, not secret lifecycle management.
5. This is a metadata-level change, deployable without downtime, but requires a Lambda function update (new deployment/version).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaEnvironmentEncryptionSettings.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaEnvironmentEncryptionSettings.py
- AWS docs: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption
