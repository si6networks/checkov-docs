# CKV_AWS_311: Ensure that CodeBuild S3 logs are encrypted

## Severity
**HIGH** (score: 7.5/10)

Unencrypted CodeBuild S3 logs risk exposing build output and diagnostic data at rest, but logs are typically lower sensitivity than primary data stores.

## Summary
This check ensures that when an AWS CodeBuild project writes its build logs to S3, encryption of those logs is not explicitly disabled.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_codebuild_project`

## Why it matters
CodeBuild build logs frequently contain sensitive information: environment variable values printed by build scripts, dependency download URLs with embedded credentials, stack traces, internal hostnames, and sometimes secrets accidentally echoed during debugging. If these logs are stored in S3 with encryption disabled, anyone with access to the underlying S3 objects (through a misconfigured bucket policy, an over-permissioned IAM role, or backup/replication targets) can read that sensitive data at rest without needing KMS key access. Disabling encryption removes a layer of defense-in-depth that would otherwise require both S3 object access **and** decryption key access to expose the data — directly weakening controls around encrypting sensitive data at rest (NIST 800-53 SC-28).

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the nested key `logs_config[0].s3_logs[0].encryption_disabled`:
- **FAIL** if `encryption_disabled` is explicitly set to `true`.
- **PASS** if it is `false`, unset, or the `s3_logs` block is absent entirely (the forbidden-value check only fails on an explicit `true`).

## Non-compliant example
```hcl
resource "aws_codebuild_project" "example" {
  name          = "example-build"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  source {
    type     = "GITHUB"
    location = "https://github.com/example/example-repo.git"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"
    type            = "LINUX_CONTAINER"
  }

  logs_config {
    s3_logs {
      status              = "ENABLED"
      location            = "${aws_s3_bucket.build_logs.id}/build-log"
      encryption_disabled = true          # explicitly turns off encryption
    }
  }
}
```

## Remediated example
```hcl
resource "aws_codebuild_project" "example" {
  name          = "example-build"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  source {
    type     = "GITHUB"
    location = "https://github.com/example/example-repo.git"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  logs_config {
    s3_logs {
      status              = "ENABLED"
      location            = "${aws_s3_bucket.build_logs.id}/build-log"
      encryption_disabled = false         # or simply omit this argument
    }
  }
}
```

## Remediation steps
1. In the `logs_config.s3_logs` block, remove `encryption_disabled = true` or explicitly set it to `false`.
2. Ensure the target S3 bucket (`aws_s3_bucket.build_logs` above) itself has default SSE (SSE-S3 or SSE-KMS) enabled via `aws_s3_bucket_server_side_encryption_configuration`, since S3 log delivery uses the bucket's default encryption settings.
3. If using a customer-managed KMS key for the bucket, verify the CodeBuild service role has `kms:GenerateDataKey`/`kms:Decrypt` permissions on that key.
4. No resource replacement is required — this is an in-place update to the CodeBuild project.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodebuildS3LogsEncrypted.py
- AWS docs: https://docs.aws.amazon.com/codebuild/latest/userguide/change-project-console.html#change-project-console-logs
