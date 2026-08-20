# CKV_LIN_1: Ensure no hard coded Linode tokens exist in provider
## Severity
**CRITICAL** (score: 9.5/10)

A hardcoded Linode API token committed in Terraform provider configuration is a directly exploitable exposed credential that grants an attacker full account/API access if the source is leaked or the repository is exposed.

## Summary
This check scans the Terraform `provider "linode"` block for a hardcoded API token value that matches Linode's token format, flagging it as an exposed secret.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `provider` block configuration type, specifically `provider "linode"` (the Linode Terraform provider used to manage Linode cloud resources — instances, NodeBalancers, LKE clusters, object storage, etc.).

## Why it matters
Linode Personal Access Tokens grant API-level control over the account's entire infrastructure — creating/destroying Linodes, reading/modifying DNS, accessing object storage, and billing operations, depending on token scope. Hardcoding a token directly in a `provider` block means the secret is committed to version control in plaintext: anyone with read access to the repository (including its full git history, even after later "removal") can extract and reuse the token. Since Terraform provider blocks are frequently shared, templated, or copy-pasted between environments and repositories, and are often checked into source control without the same scrutiny as application secrets, this is a common and severe path for credential leakage — equivalent in blast radius to leaking a cloud account's root API key.

## How Checkov evaluates this
The check (`LinodeCredentials`, a `BaseProviderCheck`) inspects the `provider "linode"` configuration block:
1. It looks for a `token` field in the provider configuration.
2. If present, it takes the field's value and matches it against `linode_token_pattern` (a regex from `checkov.common.models.consts` recognizing Linode's token format — a fixed-length hexadecimal string).
3. If the value matches the pattern (i.e., looks like a literal, real Linode token rather than a variable reference or interpolation), the check FAILS and stores the discovered value under a `<id>_secret` key for reporting/masking purposes.
4. If no `token` field is present, or its value doesn't match the token pattern (e.g., it's a Terraform variable reference like `var.linode_token`, which won't match a fixed hex-token regex), the check PASSES.

## Non-compliant example
```hcl
provider "linode" {
  token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}

resource "linode_instance" "web" {
  label  = "web-1"
  region = "us-east"
  type   = "g6-standard-2"
}
```

## Remediated example
```hcl
variable "linode_token" {
  description = "Linode Personal Access Token"
  type        = string
  sensitive   = true
}

provider "linode" {
  token = var.linode_token
}

resource "linode_instance" "web" {
  label  = "web-1"
  region = "us-east"
  type   = "g6-standard-2"
}
```

```bash
# supplied at runtime, never committed to source control
export TF_VAR_linode_token="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

## Remediation steps
1. Remove the literal token value from the `provider "linode"` block entirely.
2. Replace it with a `variable` reference (marked `sensitive = true`) or an environment-variable-driven input (`TF_VAR_linode_token`), or omit `token` entirely and rely on the `LINODE_TOKEN` environment variable, which the Linode provider reads automatically.
3. If the token was ever committed to git, treat it as compromised: revoke/regenerate the token in the Linode Cloud Manager (API Tokens page) immediately — removing it from the current file does not remove it from git history.
4. Store the token in a secrets manager (Vault, AWS Secrets Manager, etc.) or your CI/CD platform's encrypted secrets store, and inject it at plan/apply time rather than checking it into `.tf` files.
5. Add `*.tfvars` files containing real secrets to `.gitignore`, and consider a pre-commit secret-scanning hook to catch future accidental commits.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/linode/credentials.py)
- [Linode Terraform provider documentation](https://registry.terraform.io/providers/linode/linode/latest/docs)
