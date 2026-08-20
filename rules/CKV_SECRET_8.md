# CKV_SECRET_8: IBM COS HMAC Credentials

## Severity
**LOW** (score: 2.0/10)

IBM Cloud Object Storage HMAC credentials function like S3 access keys and grant direct programmatic read/write access to object storage buckets, so their exposure enables immediate unauthorized data access or exfiltration.

## Summary
This check scans files for strings matching the format of IBM Cloud Object Storage (COS) HMAC access key ID / secret access key pairs, flagging any match as a hardcoded credential.

## Applicability
**Checkov framework(s):** `secrets`

This is a built-in Checkov **secrets scanning** check (framework: `secrets`) that runs against any text file included in a repository/directory scan — source code, IaC templates (Terraform provider/resource blocks, CloudFormation, Kubernetes manifests/Secrets), CI/CD configuration, shell scripts, and application config files. It is content/pattern-based, not scoped to a specific resource type ("entities": `secrets`).

## Why it matters
IBM COS HMAC credentials are S3-compatible access-key/secret-key pairs used to authenticate directly against IBM Cloud Object Storage's S3-compatible API, bypassing IAM token exchange entirely. Because they behave like static AWS-style access keys, they are long-lived and, once leaked, remain usable until explicitly revoked, with no built-in expiry to limit exposure. A leaked HMAC credential grants an attacker programmatic read/write/delete access to whatever COS buckets the credential's associated service ID is authorized for — enabling data exfiltration (reading sensitive stored objects), data destruction, or use of the storage bucket as a staging point for further attacks (e.g. malware hosting). Because these credentials are frequently embedded in application config or infrastructure-as-code for S3-compatible tooling, they are a common and high-impact class of accidental repository leak.

## How Checkov evaluates this
Checkov relies on the `detect-secrets` plugin architecture; the plugin registered for this check applies a regular expression matching the known structural format of IBM COS HMAC access-key-ID / secret-access-key values against every line of a scanned file. A structural match causes Checkov to report **FAILED** for `CKV_SECRET_8` at that location. There is no separate pass/fail resource state beyond presence or absence of a matching string — files with no match simply produce no finding.

## Non-compliant example
```hcl
# main.tf — HMAC credentials hardcoded for an S3-compatible client provider
resource "null_resource" "cos_config" {
  provisioner "local-exec" {
    command = "aws --endpoint-url https://s3.us-south.cloud-object-storage.appdomain.cloud s3 ls"
    environment = {
      AWS_ACCESS_KEY_ID     = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
      AWS_SECRET_ACCESS_KEY = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
    }
  }
}
```

## Remediated example
```hcl
# main.tf — credentials injected via variables sourced from a secrets manager
resource "null_resource" "cos_config" {
  provisioner "local-exec" {
    command = "aws --endpoint-url https://s3.us-south.cloud-object-storage.appdomain.cloud s3 ls"
    environment = {
      AWS_ACCESS_KEY_ID     = var.cos_hmac_access_key_id
      AWS_SECRET_ACCESS_KEY = var.cos_hmac_secret_access_key
    }
  }
}

variable "cos_hmac_access_key_id" {
  type      = string
  sensitive = true
}

variable "cos_hmac_secret_access_key" {
  type      = string
  sensitive = true
}
```

## Remediation steps
1. Treat any committed HMAC key pair as compromised: rotate/regenerate the HMAC credentials for the affected COS service credential in IBM Cloud immediately.
2. Remove the literal keys from tracked files and purge them from git history (`git filter-repo` / BFG Repo-Cleaner).
3. Inject credentials at runtime via environment variables, CI/CD masked secrets, or a secrets manager (Vault, IBM Cloud Secrets Manager) rather than embedding them in `.tf`/config files.
4. Mark corresponding Terraform variables `sensitive = true` so values are not echoed in plan/apply output.
5. Prefer IAM-based (token) authentication over static HMAC keys where the tooling supports it, since IAM tokens are short-lived and reduce the impact of a leak.
6. Add pre-commit secret scanning and a `detect-secrets` baseline to catch this class of leak before it is committed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py
