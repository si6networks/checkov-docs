# CKV2_AWS_64: Ensure KMS key Policy is defined

## Severity
**MEDIUM** (score: 5.0/10)

A KMS key with no explicit key policy falls back to permissive default behavior that can grant broad account-wide access to the key, undermining the access controls meant to protect everything the key encrypts.

## Summary
This check requires every `aws_kms_key` to have an explicit key policy defined — either inline via the `policy` attribute or via a connected `aws_kms_key_policy` resource — rather than relying on the provider's implicit default policy.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_kms_key` (satisfied by an inline `policy` attribute OR a connection to `aws_kms_key_policy`)

## Why it matters
If `aws_kms_key` is created without a `policy`, Terraform (and AWS) falls back to a default key policy that grants the AWS account **root user** full `kms:*` permissions on the key — which, combined with IAM policies elsewhere in the account, can result in far broader access to the key than intended, since any IAM principal with sufficiently broad IAM permissions (not just explicit key-policy grants) can then use or manage the key. KMS keys guard the confidentiality of everything encrypted with them — database credentials, S3 objects, EBS volumes, Secrets Manager secrets — so an overly permissive or accidentally-default key policy can silently widen who can decrypt sensitive data or who can disable/schedule deletion of the key (a straightforward denial-of-service or data-destruction vector, since deleting a KMS key makes all data encrypted under it permanently unrecoverable). Explicitly defining the key policy forces developers to consciously scope which principals get `kms:Decrypt`, `kms:Encrypt`, `kms:ScheduleKeyDeletion`, etc.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with an `or` of two satisfying conditions on `aws_kms_key`:
1. **Inline path:** the `policy` attribute exists directly on the `aws_kms_key` resource.
2. **Connection path:** the resource is `aws_kms_key` and has a graph connection to a separate `aws_kms_key_policy` resource (the decoupled policy-attachment resource introduced in newer AWS provider versions).

If neither an inline `policy` nor a connected `aws_kms_key_policy` is present, the check **FAILS** — meaning the key is relying on the implicit default policy.

## Non-compliant example
```hcl
resource "aws_kms_key" "app_data" {
  description             = "CMK for application data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  # No policy attribute, no aws_kms_key_policy -> FAILS, uses default policy
}
```

## Remediated example
```hcl
resource "aws_kms_key" "app_data" {
  description             = "CMK for application data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowAppRoleToUseKey"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.app.arn }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}
```

## Remediation steps
1. Add an explicit `policy` attribute (JSON key policy) to every `aws_kms_key`, or attach one via a separate `aws_kms_key_policy` resource.
2. Scope the policy narrowly: grant `kms:Decrypt`/`kms:GenerateDataKey` only to the specific IAM roles/services that need to use the key, and restrict `kms:ScheduleKeyDeletion`/`kms:DisableKey`/`kms:PutKeyPolicy` to trusted administrative principals only.
3. Always retain a root-account administrative statement (as AWS strongly recommends) to avoid permanently locking yourself out of managing the key.
4. Applying a key policy to an existing key is a non-destructive, in-place update.
5. Consider using `aws_kms_key_policy` (the standalone resource) rather than inline `policy` when the policy needs to reference resources created after the key, to avoid Terraform dependency-ordering issues.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/KmsKeyPolicyIsDefined.json
- AWS docs: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
