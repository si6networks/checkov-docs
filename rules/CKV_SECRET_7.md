# CKV_SECRET_7: IBM Cloud IAM Key

## Severity
**HIGH** (score: 7.5/10)

An exposed IBM Cloud IAM API key grants direct, credentialed access to IAM-scoped cloud resources and services, making its leakage equivalent to handing an attacker a working account credential.

## Summary
This check scans scanned files for strings matching the format of an IBM Cloud IAM API key, flagging any match as a hardcoded credential.

## Applicability
This is a built-in Checkov **secrets scanning** check (framework: `secrets`) that runs against any text file included in a repository/directory scan — source code, configuration files, IaC templates (Terraform, CloudFormation, ARM/Bicep, Kubernetes manifests), CI/CD pipeline definitions, and plaintext files. It is pattern/content-based rather than tied to a specific resource type ("entities": `secrets`).

## Why it matters
An IBM Cloud IAM API key is a long-lived bearer credential that can be exchanged for access tokens scoped to whatever IAM policies are attached to the identity that owns the key — potentially spanning multiple IBM Cloud services, resource groups, or the entire account depending on how broadly the key's access policies were defined. Because these keys are often generated once and embedded directly into deployment scripts, Terraform provider blocks, or CI pipeline environment variables for convenience, they are a common source of accidental exposure in public or improperly-permissioned repositories. A leaked IAM key gives an attacker the same programmatic access as the legitimate automation that uses it — potentially enabling data exfiltration, resource creation (cryptomining), or destruction of cloud infrastructure — without needing to compromise any additional system.

## How Checkov evaluates this
Checkov integrates the `detect-secrets` plugin ecosystem; the plugin registered for this check applies a regular expression tuned to the known structure/prefix of IBM Cloud IAM API keys against each line of a scanned file. A structural match causes Checkov to report **FAILED** for `CKV_SECRET_7` at that line/file. Lines with no matching pattern produce no finding — there is no separate "pass" resource state, since this is a presence/absence secrets detector rather than a resource-attribute check.

## Non-compliant example
```hcl
# provider.tf — IBM Cloud IAM key hardcoded directly in the provider block
provider "ibm" {
  ibmcloud_api_key = "IBM_APIKey_x7Kp2nQ9vT4mR8wL1sD6fG3hJ0aZ5cE"
  region            = "us-south"
}
```

## Remediated example
```hcl
# provider.tf — key supplied via environment variable / variable, never hardcoded
provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region            = "us-south"
}

variable "ibmcloud_api_key" {
  description = "IBM Cloud IAM API key, injected via TF_VAR_ibmcloud_api_key"
  type        = string
  sensitive   = true
}
```

## Remediation steps
1. Treat any committed IAM key as compromised: revoke/delete it in IBM Cloud IAM and issue a new key immediately.
2. Remove the literal key from all tracked files and purge it from git history (`git filter-repo` / BFG Repo-Cleaner).
3. Supply the key at runtime via environment variables (`IBMCLOUD_API_KEY`), a CI/CD masked secret, or a secrets manager — never as a literal in `.tf`, `.tfvars`, or scripts.
4. Mark corresponding Terraform variables `sensitive = true` to keep the value out of plan/apply logs.
5. Scope the underlying IAM key to the minimum access policy required (avoid account-owner or broad "Editor" roles) so that even a future leak has limited blast radius.
6. Enable pre-commit secret scanning (`detect-secrets`) and a `.secrets.baseline` to catch this class of leak before it reaches the remote repository.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py
