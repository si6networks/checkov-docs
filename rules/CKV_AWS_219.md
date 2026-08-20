# CKV_AWS_219: Ensure CodePipeline Artifact store is using a KMS CMK
## Severity
**LOW** (score: 2.0/10)

CodePipeline artifacts are encrypted by a default S3/KMS key regardless, so missing a customer-managed key mainly reduces control over key access and rotation for build artifacts that may contain proprietary code or configuration.

## Summary
This check ensures that an AWS CodePipeline (`aws_codepipeline`) resource specifies a KMS key for its artifact store encryption, rather than relying on the default S3/CodePipeline-managed encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_codepipeline`

## Why it matters
CodePipeline stores build/deployment artifacts (compiled binaries, packaged application code, container image references, configuration files, and sometimes embedded secrets or credentials used during the CI/CD process) in an S3-backed artifact store. Without an explicit customer-managed KMS key, artifacts are encrypted using S3-managed keys (SSE-S3) or the pipeline's default settings, which your organization does not control: you cannot enforce a custom key policy restricting which IAM principals/roles can decrypt artifacts, cannot get detailed CloudTrail audit logs of every decrypt operation performed on pipeline artifacts, and cannot immediately revoke access to artifacts by disabling a key during an incident. Since CI/CD artifact stores are a high-value target for supply-chain attacks (an attacker who can read or tamper with build artifacts can inject malicious code into what eventually gets deployed to production), controlling encryption and access to this store with a CMK is an important layer of defense.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `artifact_store/[0]/encryption_key/[0]/id`:
- The expected value is `ANY_VALUE`, meaning any non-empty value for the encryption key ID satisfies the check.
- If `artifact_store.encryption_key.id` is set to any value, the check **PASSES**.
- If the `encryption_key` block (or its `id`) is absent, the check **FAILS** (default missing-block behavior).

## Non-compliant example
```hcl
resource "aws_codepipeline" "example" {
  name     = "example-pipeline"
  role_arn = aws_iam_role.codepipeline.arn

  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"
  }

  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source_output"]
      configuration = {
        ConnectionArn = aws_codestarconnections_connection.example.arn
        FullRepositoryId = "example-org/example-repo"
        BranchName       = "main"
      }
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "pipeline_cmk" {
  description             = "CMK for CodePipeline artifact encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_codepipeline" "example" {
  name     = "example-pipeline"
  role_arn = aws_iam_role.codepipeline.arn

  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"

    encryption_key {
      id   = aws_kms_key.pipeline_cmk.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source_output"]
      configuration = {
        ConnectionArn = aws_codestarconnections_connection.example.arn
        FullRepositoryId = "example-org/example-repo"
        BranchName       = "main"
      }
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key with a policy restricting decrypt access to the CodePipeline service role and other legitimate principals.
2. Ensure the pipeline's IAM role and the artifact store's S3 bucket policy both grant the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions to use the CMK.
3. Add an `encryption_key { id = <kms_key_arn>, type = "KMS" }` block inside `artifact_store` on the `aws_codepipeline` resource.
4. Grant `kms:Decrypt` to any downstream services/roles (CodeBuild, CodeDeploy, Lambda deploy actions, etc.) that need to read artifacts from the store.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodePipelineArtifactsEncrypted.py)
- [AWS CodePipeline: Encryption at rest for artifacts](https://docs.aws.amazon.com/codepipeline/latest/userguide/S3-artifact-encryption.html)
