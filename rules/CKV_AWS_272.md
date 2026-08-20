# CKV_AWS_272: Ensure AWS Lambda function is configured to validate code-signing

## Severity
**HIGH** (score: 7.5/10)

Without code-signing enforcement, Lambda will run any code package uploaded by a principal with deploy permissions with no cryptographic provenance check, creating a direct supply-chain path for unauthorized or tampered code to execute in production.

## Summary
This check ensures a Lambda function specifies a code-signing configuration (`code_signing_config_arn`) so that AWS Lambda validates the integrity and provenance of deployed code before accepting it.

## Applicability
- **Terraform**: resource `aws_lambda_function`

## Why it matters
Without code signing, Lambda will accept and run any deployment package (ZIP file or container image reference) that a principal with `lambda:UpdateFunctionCode`/`lambda:CreateFunction` permission uploads — with no cryptographic verification that the code came from an approved build pipeline or has not been tampered with. This is a supply-chain security gap: if an attacker compromises CI/CD credentials, a developer's local AWS credentials, or exploits an overly broad IAM policy, they could deploy malicious code directly into a running Lambda function without any signature check catching it. AWS Lambda code signing (via AWS Signer) lets you enforce that only packages signed by a designated, trusted signing profile can be deployed, blocking unauthorized or unsigned code from ever executing — a direct mitigation against supply-chain and insider-threat code injection.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the `code_signing_config_arn` attribute:
- **PASS**: `code_signing_config_arn` is set to any non-empty value.
- **FAIL**: `code_signing_config_arn` is absent or empty.

## Non-compliant example
```hcl
resource "aws_lambda_function" "processor" {
  function_name = "order-processor"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "function.zip"
  # no code_signing_config_arn set
}
```

## Remediated example
```hcl
resource "aws_signer_signing_profile" "lambda_signing" {
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_lambda_code_signing_config" "trusted" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda_signing.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

resource "aws_lambda_function" "processor" {
  function_name            = "order-processor"
  role                      = aws_iam_role.lambda.arn
  handler                   = "index.handler"
  runtime                   = "nodejs18.x"
  filename                  = "function.zip"
  code_signing_config_arn   = aws_lambda_code_signing_config.trusted.arn
}
```

## Remediation steps
1. Create an AWS Signer signing profile representing your trusted build/CI pipeline (`aws_signer_signing_profile`).
2. Create an `aws_lambda_code_signing_config` referencing that signing profile, with `untrusted_artifact_on_deployment = "Enforce"` (use `"Warn"` only temporarily during migration, since it does not block deployment).
3. Add `code_signing_config_arn` to each `aws_lambda_function` resource, pointing at the code signing config.
4. Update your CI/CD pipeline to sign build artifacts with AWS Signer using the matching signing profile before uploading to Lambda — unsigned or differently-signed deployments will be rejected once enforcement is active.
5. Roll out with `"Warn"` first in non-critical functions to validate your pipeline correctly signs artifacts, then switch to `"Enforce"` once confirmed, to avoid breaking deployments unexpectedly.
6. No resource replacement is required for the Lambda function itself, but deployments will start failing until your build pipeline is updated to sign artifacts.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaCodeSigningConfigured.py
- AWS documentation: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
