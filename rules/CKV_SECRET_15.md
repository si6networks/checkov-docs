# CKV_SECRET_15: SoftLayer Credentials

## Severity
**LOW** (score: 2.0/10)

A leaked SoftLayer/IBM Cloud API key grants programmatic control over bare-metal/VM infrastructure and billing, letting an attacker provision resources at the victim's expense or access/destroy existing infrastructure.

## Summary
This check scans file contents for hardcoded IBM Cloud/SoftLayer API credentials (username plus API key), flagging static infrastructure-provider credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (Terraform provider blocks, config files, scripts, CI pipeline definitions, `.softlayer`/`.slcli` config, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
SoftLayer (now IBM Cloud Classic Infrastructure) API credentials grant programmatic control over an organization's bare-metal servers, VMs, networking, and billing within IBM Cloud's classic infrastructure. A leaked SoftLayer username/API-key pair allows an attacker to provision expensive compute resources at the victim's expense (a common monetization pattern for leaked cloud credentials — cryptomining or spam infrastructure), access or destroy existing infrastructure, and view account billing/PII details. Because these credentials are typically long-lived API keys tied directly to an account (not short-lived tokens), the exposure window persists until a human notices and manually regenerates the key.

## How Checkov evaluates this
The secrets scanner matches the structural signature of SoftLayer/IBM Cloud Classic credentials — typically a `username`/`api_key` pair where the API key is a fixed-length hexadecimal string, often appearing together in config file formats like `.softlayer`, `SL_API_KEY`/`SL_USERNAME` environment assignments, or Terraform `provider "softlayer"` / `provider "ibm"` blocks. A match of this credential-shaped pattern in scanned file content is reported as a FAIL at that file/line.

## Non-compliant example
```hcl
provider "softlayer" {
  username = "myorg_admin"
  api_key  = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

## Remediated example
```hcl
provider "softlayer" {
  # username and api_key sourced from SL_USERNAME / SL_API_KEY environment
  # variables, populated by a secrets manager — never hardcoded.
}
```

## Remediation steps
1. Regenerate the exposed SoftLayer/IBM Cloud API key immediately in the IBM Cloud console (Manage → Access (IAM) → API keys, or classic infrastructure account settings) — assume it is compromised.
2. Remove the hardcoded `username`/`api_key` from the provider block or config file and rely on the provider's standard environment-variable lookup (`SL_USERNAME`/`SL_API_KEY`) sourced from a secrets manager or CI/CD masked secret.
3. Purge the secret from git history if it was ever committed/pushed.
4. Review billing and provisioning activity in the IBM Cloud account for any unauthorized resource creation during the exposure window.
5. Where possible, scope IAM policies tightly for the identity associated with the key rather than relying on account-wide credentials.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
