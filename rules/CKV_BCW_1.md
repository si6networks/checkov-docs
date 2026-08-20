# CKV_BCW_1: Ensure no hard coded API token exist in the provider
## Severity
**CRITICAL** (score: 9.5/10)

A hardcoded Bridgecrew API token committed in Terraform provider configuration is a plaintext credential that, if leaked via version control, grants an attacker direct programmatic access to the account.

## Summary
This check verifies that the Terraform `bridgecrew` provider block does not contain a hard-coded Bridgecrew/Prisma Cloud API token literal in source code.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `provider "bridgecrew"` blocks (provider-type check, inspects the `token` argument)

## Why it matters
The `bridgecrew` provider's `token` argument authenticates Terraform to the Bridgecrew (now Prisma Cloud) platform API. Hard-coding this token directly in a `.tf` file is a classic secrets-in-code anti-pattern:
- Terraform configuration files are routinely committed to version control (Git), shared across teams, and sometimes made public in open-source repos or misconfigured private repos — a hard-coded token becomes permanently embedded in git history even if later removed.
- Anyone with read access to the repository (including CI logs, forks, or a leaked archive) obtains a live credential capable of interacting with the Bridgecrew/Prisma Cloud API on the organization's behalf.
- Rotating a leaked hard-coded token requires finding and scrubbing every place it was committed (including history), which is operationally painful compared to rotating a value stored in a secrets manager or environment variable.

Using an environment variable, a `.tfvars` file excluded from version control, or a secrets manager reference instead keeps the credential out of source control entirely.

## How Checkov evaluates this
The check runs `scan_provider_conf` against the `bridgecrew` provider's configuration and calls a helper `secret_found(conf, "token", bridgecrew_token_pattern)`. This helper:
1. Looks up the `token` field in the provider config.
2. Matches its value against `bridgecrew_token_pattern` — a regex recognizing the specific format of a Bridgecrew API token.
3. If the value matches that pattern (i.e., it looks like a literal, well-formed token string rather than an interpolated reference such as `var.bridgecrew_token`), the check FAILS.
4. If no match (e.g., the token is provided via a variable reference, has been redacted, or the field is absent), the check PASSES.

In other words: Checkov isn't just checking "is `token` set" — it specifically pattern-matches for what looks like a **literal hard-coded secret value**, as opposed to a variable/expression reference.

## Non-compliant example
```hcl
provider "bridgecrew" {
  api_url = "https://www.bridgecrew.cloud/api/v1"
  token   = "12345678-abcd-1234-abcd-1234567890ab"   # <-- hard-coded literal token
}
```

## Remediated example
```hcl
provider "bridgecrew" {
  api_url = "https://www.bridgecrew.cloud/api/v1"
  token   = var.bridgecrew_api_token   # <-- sourced from a variable, not hard-coded
}

variable "bridgecrew_api_token" {
  type      = string
  sensitive = true
}
```
```bash
# supplied at runtime, e.g. via environment variable, never committed:
export TF_VAR_bridgecrew_api_token="12345678-abcd-1234-abcd-1234567890ab"
```

## Remediation steps
1. Remove the literal token string from the `provider "bridgecrew"` block.
2. Replace it with a variable reference (`var.bridgecrew_api_token`), marking the variable `sensitive = true`.
3. Supply the actual token value via `TF_VAR_*` environment variables, a `.tfvars` file that is git-ignored, or a secrets manager/CI secret store integration.
4. If a token was ever committed to version control, treat it as compromised: revoke/rotate it in the Bridgecrew/Prisma Cloud console immediately, and consider scrubbing it from git history.
5. Add a pre-commit secret-scanning hook (e.g. `detect-secrets`, `gitleaks`) to catch similar hard-coded credentials before they're committed in the future.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/bridgecrew/credentials.py
