# CKV_AWS_221: Ensure CodeArtifact Domain is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

A CodeArtifact domain without a customer-managed KMS key still benefits from default encryption, so the gap is primarily reduced control over key rotation and access for stored packages rather than an unencrypted store.

## Summary
This check ensures that an AWS CodeArtifact domain (`aws_codeartifact_domain`) is configured with a customer-managed KMS key for encrypting its stored package assets and metadata.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_codeartifact_domain`

## Why it matters
A CodeArtifact domain is the top-level container for one or more package repositories that store your organization's software packages (npm, PyPI, Maven, NuGet, etc.), including internal proprietary code and any credentials embedded in package metadata or configuration. Without a customer-managed key, encryption defaults to an AWS-owned key that your organization cannot govern: you cannot scope a key policy to specific IAM principals, cannot audit key usage via CloudTrail with the same granularity, and cannot revoke access in an incident by disabling the key. Since CodeArtifact is a software supply-chain component — an attacker who gains read access to stored packages could exfiltrate proprietary source code, and an attacker with write access to unprotected repositories could plant malicious package versions — controlling the encryption key used to protect this data is an important part of supply-chain security and compliance requirements around key custody.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `encryption_key` attribute (note: this resource uses a differently-named attribute than the more common `kms_key_id`, as the check's own source comment wryly notes):
- The expected value is `ANY_VALUE`, meaning any non-empty value satisfies the check.
- If `encryption_key` is set to any value, the check **PASSES**.
- If `encryption_key` is absent, the check **FAILS** (default missing-block behavior).

## Non-compliant example
```hcl
resource "aws_codeartifact_domain" "example" {
  domain = "example-domain"
}
```

## Remediated example
```hcl
resource "aws_kms_key" "codeartifact_cmk" {
  description             = "CMK for CodeArtifact domain encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_codeartifact_domain" "example" {
  domain         = "example-domain"
  encryption_key = aws_kms_key.codeartifact_cmk.arn
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key with a key policy restricting decrypt/encrypt access to the IAM roles/users that legitimately need to publish or consume packages.
2. Set the `encryption_key` attribute on the `aws_codeartifact_domain` resource to that key's ARN.
3. Note: `encryption_key` can only be set at domain creation time — changing it on an existing domain requires replacing the resource, which will require re-provisioning all downstream repositories under that domain; plan for a migration rather than an in-place change.
4. Ensure any CI/CD roles or developer IAM principals that publish/fetch packages have the necessary `kms:Decrypt` and `kms:GenerateDataKey` permissions on the CMK.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodeArtifactDomainEncryptedWithCMK.py)
- [AWS CodeArtifact: Encryption at rest](https://docs.aws.amazon.com/codeartifact/latest/ug/encryption-at-rest.html)
