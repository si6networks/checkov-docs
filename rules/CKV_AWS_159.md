# CKV_AWS_159: Ensure that Athena Workgroup is encrypted
## Severity
**MEDIUM** (score: 5.0/10)

Athena workgroup encryption protects query results and metadata written to S3, which can reflect the same sensitivity as the underlying data being queried, so its absence weakens at-rest protection for potentially sensitive query output.

## Summary
This check verifies that an Amazon Athena workgroup's result configuration specifies an encryption option for query results.

## Applicability
Terraform only. Applies to the `aws_athena_workgroup` resource.

## Why it matters
Athena stores query results in S3, and those results often contain the actual data returned by a query — which can include sensitive rows from data lakes (PII, financial data, security logs) depending on what analysts query. If the workgroup's result configuration does not enforce encryption, query result objects may be written to S3 relying solely on whatever default bucket-level settings exist (or none at all), meaning results could end up unencrypted or encrypted with a weaker/inconsistent scheme than intended, and different analysts/queries could produce inconsistently protected outputs. Setting the encryption option at the workgroup level centralizes and enforces a consistent encryption posture for every query result written through that workgroup, regardless of individual analyst behavior or per-query configuration.

## How Checkov evaluates this
`BaseResourceValueCheck` with `ANY_VALUE` as expected value, inspecting the deeply nested attribute path `configuration[0].result_configuration[0].encryption_configuration[0].encryption_option`. Passes if this path resolves to any non-empty value (e.g. `SSE_S3`, `SSE_KMS`, or `CSE_KMS`); fails if the encryption configuration block (or the `encryption_option` within it) is absent.

## Non-compliant example
```hcl
resource "aws_athena_workgroup" "analysts" {
  name = "analysts-workgroup"

  configuration {
    result_configuration {
      output_location = "s3://athena-results-bucket/analysts/"
      # no encryption_configuration block
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "athena" {
  description             = "CMK for Athena query results"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_athena_workgroup" "analysts" {
  name = "analysts-workgroup"

  configuration {
    result_configuration {
      output_location = "s3://athena-results-bucket/analysts/"

      encryption_configuration { # <-- added
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.athena.arn
      }
    }
  }
}
```

## Remediation steps
1. Add an `encryption_configuration` block inside `result_configuration` for every `aws_athena_workgroup`.
2. Choose `encryption_option`: `SSE_S3` for Amazon-managed encryption, `SSE_KMS` for server-side encryption with a customer-managed KMS key (recommended for sensitive data, requires `kms_key_arn`), or `CSE_KMS` for client-side encryption.
3. Ensure the IAM roles used by Athena/analysts have `kms:GenerateDataKey`/`kms:Decrypt` permissions on the chosen key if using `SSE_KMS`/`CSE_KMS`.
4. Also verify `enforce_workgroup_configuration = true` so individual query-level settings cannot override the workgroup's encryption requirement.
5. Apply the same encryption configuration consistently to the underlying results S3 bucket's default encryption as defense-in-depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AthenaWorkgroupEncryption.py
- AWS docs: https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html
