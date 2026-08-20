# CKV_AWS_45: Ensure no hard-coded secrets exist in Lambda environment
## Severity
**CRITICAL** (score: 9.3/10)

Hard-coded secrets in Lambda environment variables are stored largely in cleartext in the function configuration and are directly retrievable by anyone with read access to the function, functioning as an exposed credential.

## Summary
This check scans Lambda function environment variables for values that look like hard-coded secrets (API keys, credentials, tokens), which should be stored in a secrets manager instead.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Lambda::Function`, `AWS::Serverless::Function` (CloudFormation/SAM), `aws_lambda_function` (Terraform) — specifically the `Environment`/`environment` variables block.

## Why it matters
Lambda environment variables are visible in plaintext to anyone with `lambda:GetFunctionConfiguration` permission (unless the variables are further encrypted with a customer KMS key, which most teams don't bother with) and appear in Infrastructure-as-Code source, in CloudFormation/Terraform state files, and in CI/CD logs during deployment. Embedding an API key, database password, or access token directly as an environment variable value in code means that secret is committed to version control history, is readable by anyone with console/API read access to the function configuration, and cannot be centrally rotated, audited, or access-controlled the way a secrets manager entry can. This is a very common source of credential leakage in serverless applications, especially since teams often copy example configs from documentation without replacing placeholder-looking secrets with real secret references.

## How Checkov evaluates this
Both implementations are `BaseResourceCheck`s that scan environment variable **values** through a secret-detection heuristic (`get_secrets_from_string` / `string_has_secrets`, matching AWS and general credential patterns like access keys, private keys, or high-entropy strings resembling tokens):
- **CloudFormation:** for each key/value in `Properties/Environment/Variables`, skips values that are themselves intrinsic functions (dicts, e.g. `!Ref`) or start with `handler.`/`git.` (common non-secret placeholder prefixes), then runs the secret-detection heuristic on the remaining string values. Any match → **FAIL**.
- **Terraform:** for each key/value in the `environment.variables` block, runs the same heuristic on string values. Any match → **FAIL**.
- No matches found (or no environment variables defined) → **PASS**.

## Non-compliant example
```hcl
resource "aws_lambda_function" "example" {
  function_name = "example-fn"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"

  environment {
    variables = {
      STRIPE_API_KEY = "sk_live_51H8xJ2eZvKYlo2C0abcdEXAMPLEKEY1234567890"
    }
  }
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "example" {
  function_name = "example-fn"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"

  environment {
    variables = {
      STRIPE_SECRET_ARN = aws_secretsmanager_secret.stripe_key.arn
    }
  }
}
```

## Remediation steps
1. Move the secret value into AWS Secrets Manager (or SSM Parameter Store SecureString) and pass only the secret's ARN/name as the environment variable.
2. Have the function's runtime code fetch the secret value at cold-start via the Secrets Manager/SSM SDK (consider the Secrets Manager Lambda extension for caching to reduce latency and API cost).
3. Grant the Lambda's execution role `secretsmanager:GetSecretValue` (or `ssm:GetParameter`) scoped to only that specific secret ARN.
4. If a real secret was ever committed this way, rotate it immediately — assume it's compromised given IaC source/state exposure.
5. If you must keep sensitive values as env vars for legacy reasons, at minimum enable Lambda's environment variable encryption with a customer-managed KMS key, though this does not fully address IaC-source exposure.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaEnvironmentCredentials.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaEnvironmentCredentials.py)
- [AWS Lambda environment variables documentation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)
