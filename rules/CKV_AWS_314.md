# CKV_AWS_314: Ensure CodeBuild project environments have a logging configuration

## Severity
**LOW** (score: 2.0/10)

Without a logging configuration, CodeBuild project executions leave no audit trail, hampering detection of malicious or anomalous activity in a pipeline that has access to source code, secrets, and deployment credentials.

## Summary
This check ensures every AWS CodeBuild project explicitly configures a logging destination (CloudWatch Logs and/or S3) rather than leaving build logging unconfigured.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_codebuild_project`

## Why it matters
Build logs are one of the most important forensic and audit trails in a CI/CD pipeline: they show exactly what commands ran, what artifacts were produced, which credentials or IAM roles were assumed, and — critically for incident response — evidence of supply-chain tampering (e.g., an attacker injecting a malicious build step or exfiltrating secrets during the build). Without a configured logging destination, this trail may not be captured or retained at all, leaving no way to reconstruct what happened during a compromised build, no audit evidence for compliance reviews, and no operational visibility into build failures. This maps directly to auditing/accountability controls (NIST 800-53 AU-2, AU-3, AU-12) and continuous monitoring (CA-7, SI-4).

## How Checkov evaluates this
The check inspects the `logs_config` block on `aws_codebuild_project`:
- **FAIL** if `logs_config` is absent entirely.
- **PASS** if `logs_config` is present and contains either a `cloudwatch_logs` block or an `s3_logs` block (either satisfies the check — it does not require both, and does not check whether cloudwatch/s3 logging is set to `ENABLED` vs `DISABLED` within that block, only that the sub-block exists).

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
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }
  # No logs_config block -> logging destination undefined
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

  logs_config {                                     # added: explicit logging destination
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = "/aws/codebuild/example-build"
    }
  }
}
```

## Remediation steps
1. Add a `logs_config` block to the `aws_codebuild_project` resource.
2. Prefer `cloudwatch_logs { status = "ENABLED" ... }` for centralized log aggregation, retention policy, and CloudWatch Logs Insights querying.
3. If S3 storage is required instead (or in addition), add an `s3_logs` block pointing at a bucket with appropriate encryption (see CKV_AWS_311) and access controls.
4. Set an explicit CloudWatch Logs retention period (`aws_cloudwatch_log_group.retention_in_days`) so logs are neither deleted immediately nor retained indefinitely at unnecessary cost.
5. Ensure the CodeBuild service role has `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents` permissions for the target log group.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodebuildHasLogs.py
- AWS docs: https://docs.aws.amazon.com/codebuild/latest/userguide/change-project-console.html#change-project-console-logs
