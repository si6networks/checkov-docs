# CKV_AWS_147: Ensure that CodeBuild projects are encrypted using CMK
## Severity
**MEDIUM** (score: 5.0/10)

CodeBuild artifacts can include build outputs, dependency caches, or embedded configuration; missing CMK encryption weakens at-rest protection and key-level access control for that build data, though it is generally less sensitive than production customer data.

## Summary
This check verifies that an `aws_codebuild_project` resource specifies an `encryption_key` for its build artifacts, unless the project defines no artifacts at all.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `aws_codebuild_project` resource.

## Why it matters
CodeBuild build artifacts (compiled binaries, packaged application code, test reports, sometimes cached dependency archives) are stored in S3 and can contain sensitive build-time secrets, embedded credentials, or proprietary source. By default CodeBuild encrypts artifacts with an AWS-managed key, which — like other AWS-managed keys — cannot be scoped with a fine-grained key policy, cannot be independently disabled to cut off access in an incident, and generates no separately auditable CloudTrail trail distinct from the service's own key usage. Requiring an explicit customer-managed key (CMK) lets you enforce least-privilege decrypt permissions (e.g. only the CI role and specific auditors), rotate/revoke the key independently of the CodeBuild project's lifecycle, and centralize key management/monitoring alongside other CMKs in the account.

## How Checkov evaluates this
The check reads the `artifacts` block of the resource. If no `artifacts` block is present, the result is `UNKNOWN` (not applicable — nothing to encrypt). If the `artifacts` block has `type = "NO_ARTIFACTS"`, the result is also `UNKNOWN`, since there is no artifact output requiring encryption. Otherwise, it checks whether `encryption_key` is present in the resource configuration: if present, `PASSED`; if absent, `FAILED`.

## Non-compliant example
```hcl
resource "aws_codebuild_project" "app" {
  name         = "app-build"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type     = "S3"
    location = aws_s3_bucket.artifacts.id
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/example/app.git"
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "codebuild" {
  description             = "CMK for CodeBuild artifact encryption"
  deletion_window_in_days = 30
  enable_key_rotation      = true
}

resource "aws_codebuild_project" "app" {
  name           = "app-build"
  service_role   = aws_iam_role.codebuild.arn
  encryption_key = aws_kms_key.codebuild.arn # <-- added

  artifacts {
    type     = "S3"
    location = aws_s3_bucket.artifacts.id
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/example/app.git"
  }
}
```

## Remediation steps
1. Create a customer-managed KMS key (or reuse an existing organizational CMK) intended for build artifacts.
2. Add `encryption_key = aws_kms_key.<name>.arn` to the `aws_codebuild_project` resource.
3. Grant `kms:Decrypt`, `kms:GenerateDataKey*`, and related permissions in the key policy to the CodeBuild service role.
4. If artifacts are genuinely not produced (`type = "NO_ARTIFACTS"`), no change is needed — Checkov will report `UNKNOWN` rather than fail.
5. Verify no drift: CodeBuild silently falls back to the AWS-managed key if `encryption_key` is removed later.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodebuildUsesCMK.py
- AWS docs: https://docs.aws.amazon.com/codebuild/latest/userguide/security-data-protection.html
