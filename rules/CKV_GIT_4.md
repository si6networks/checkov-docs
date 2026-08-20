# CKV_GIT_4: Ensure GitHub Actions secrets are encrypted
## Severity
**HIGH** (score: 7.5/10)

Storing GitHub Actions secret values as plaintext in Terraform configuration hardcodes credentials in source and state files, exposing them to anyone with repository or state access.

## Summary
This check ensures GitHub Actions secret Terraform resources do not store a secret's value in plaintext directly in the Terraform configuration via `plaintext_value`.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `github` provider, specifically the `github_actions_environment_secret`, `github_actions_organization_secret`, and `github_actions_secret` resources, at the `plaintext_value` attribute.

## Why it matters
Terraform configuration (`.tf` files) is typically committed to version control and often shared broadly among a team, in code review tooling, and sometimes in CI logs. If a `plaintext_value` is hardcoded as a literal string, the secret's actual value becomes readable to anyone with repo read access, anyone who has ever cloned the repo (git history is essentially permanent), and is also stored in cleartext in Terraform state — meaning it's exposed in at least two additional places beyond the intended "just apply it to GitHub Actions" workflow. This directly undermines the purpose of using GitHub Actions secrets in the first place (to keep credentials out of source). A leaked cloud credential, deploy token, or signing key committed this way can lead directly to account takeover or supply-chain compromise of the CI/CD pipeline.

## How Checkov evaluates this
`SecretsEncrypted` (a `BaseResourceNegativeValueCheck`) inspects the `plaintext_value` attribute:
- If `plaintext_value` is set and the value is variable-dependent (i.e., references a Terraform variable, data source, or resource output rather than a literal — detected via `_is_variable_dependant`), the result is **UNKNOWN** (Checkov cannot statically determine whether the referenced value is itself a hardcoded secret).
- If `plaintext_value` is present but empty (`""`), it **PASSES** — this commonly happens when scanning Terraform plan output where the real value was redacted/blank.
- Otherwise, the check falls through to the base "forbidden value" logic checking `plaintext_value` against `ANY_VALUE` — meaning **any literal, non-empty, non-variable plaintext value present FAILS** the check. The recommended pattern instead is to populate the secret via `encrypted_value` (pre-encrypted with the repo's public key) or reference a value from a secure source (e.g., a secrets manager data source) rather than embedding a literal.

## Non-compliant example
```hcl
resource "github_actions_secret" "db_password" {
  repository      = "payments-service"
  secret_name     = "DB_PASSWORD"
  plaintext_value = "SuperSecretP@ssw0rd123"   # hardcoded literal secret
}
```

## Remediated example
```hcl
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/payments-service/db_password"
}

resource "github_actions_secret" "db_password" {
  repository      = "payments-service"
  secret_name     = "DB_PASSWORD"
  plaintext_value = data.aws_secretsmanager_secret_version.db_password.secret_string
  # fix: value is sourced dynamically from a secrets manager, not a literal in code
}
```

## Remediation steps
1. Never hardcode secret values as string literals in `plaintext_value`. Source them from a secrets manager (AWS Secrets Manager, GCP Secret Manager, Vault, etc.) via a Terraform data source, or from a securely-injected variable marked `sensitive = true`.
2. Alternatively, use `encrypted_value` with a value pre-encrypted using the repository's public key (`libsodium`/`sodium_encrypt` provider functions), so no plaintext ever appears in the Terraform config or plan output.
3. Immediately rotate any credential that was ever committed as a literal `plaintext_value`, since it must be treated as compromised (present in git history and Terraform state).
4. Ensure Terraform state itself is encrypted at rest and access-restricted, since even a "variable-dependent" secret will still land in plaintext in the state file.
5. If Checkov reports `UNKNOWN` due to variable dependency, manually verify the variable's source isn't itself a hardcoded default in `variables.tf` or a `.tfvars` file checked into version control.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/SecretsEncrypted.py)
- [Terraform GitHub provider: github_actions_secret](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret)
