# CKV_AWS_78: Ensure that CodeBuild Project encryption is not disabled
## Severity
**MEDIUM** (score: 5.0/10)

Disabling CodeBuild encryption leaves build artifacts and logs (which frequently contain secrets, source code, and build metadata) unencrypted at rest, increasing the impact of any storage-level compromise.

## Summary
This check fails when an AWS CodeBuild project uses S3 as its build-artifact store and has explicitly disabled encryption on those artifacts.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::CodeBuild::Project` (CloudFormation), `aws_codebuild_project` (Terraform)
- **Check type:** resource

## Why it matters
CodeBuild build artifacts frequently include compiled binaries, container images, deployment packages, and sometimes embedded configuration or secrets baked in at build time (e.g., environment-specific config files, generated credentials, or SBOM/manifest data). If artifact encryption is explicitly disabled (`EncryptionDisabled: true` / `encryption_disabled = true`) while artifacts are stored in S3, those build outputs sit in plaintext in the artifact bucket. Combined with any bucket-policy misconfiguration or overly broad IAM access to the artifact bucket, this exposes build outputs — and anything sensitive embedded in them — to unauthorized read access. Because build pipelines are a common target in supply-chain attacks, keeping artifact storage encrypted is one layer of defense against an attacker who gains read access to CI infrastructure storage.

## How Checkov evaluates this
This check has custom (non-`BaseResourceValueCheck`) logic since it only fails under a specific combination:
- **Terraform (`CodeBuildProjectEncryption.py`):**
  - If `artifacts` is missing → `UNKNOWN`.
  - Take the first `artifacts` block. If `type == ["NO_ARTIFACTS"]` → `UNKNOWN` (no artifacts to encrypt).
  - If `encryption_disabled` is present and equals `[True]` → **FAIL**.
  - Otherwise → **PASS** (this includes the case where `encryption_disabled` is absent — Terraform/AWS defaults artifact encryption to *enabled*).
- **CloudFormation (`CodeBuildProjectEncryption.py`):**
  - Only fails if `Properties.Artifacts.Type == "S3"` **and** `Properties.Artifacts.EncryptionDisabled == True`. Any other combination (no `Artifacts`, non-S3 type, or `EncryptionDisabled` false/absent) → **PASS**.

## Non-compliant example
```hcl
resource "aws_codebuild_project" "build" {
  name         = "app-build"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type                = "S3"
    location            = aws_s3_bucket.build_artifacts.id
    encryption_disabled = true
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
resource "aws_codebuild_project" "build" {
  name         = "app-build"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type     = "S3"
    location = aws_s3_bucket.build_artifacts.id
    # encryption_disabled omitted (defaults to false / encryption enabled)
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
1. Remove the `encryption_disabled = true` line entirely, or set it explicitly to `false`.
2. Optionally set `encryption_key` on the project to use a customer-managed KMS key instead of the default AWS-managed key for artifact encryption.
3. Verify the CodeBuild service role has `kms:GenerateDataKey`/`kms:Decrypt` permission if a customer-managed key is used.
4. This is a non-disruptive setting; no project replacement is required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodeBuildProjectEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CodeBuildProjectEncryption.py)
- [AWS CodeBuild artifact encryption](https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html)
