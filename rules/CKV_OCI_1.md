# CKV_OCI_1: Ensure no hard coded OCI private key in provider
## Severity
**LOW** (score: 2.0/10)

A hardcoded OCI private key password in the Terraform provider configuration exposes a credential capable of authenticating to the OCI account, risking full account compromise if the code is leaked or shared.

## Summary
This check fails when the Oracle Cloud Infrastructure (OCI) Terraform `provider` block contains a non-empty, hardcoded `private_key_password` value instead of sourcing it securely.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Entity:** the `oci` provider block
- **Check type:** provider check

## Why it matters
Terraform provider configuration is routinely committed to version control, shared across teams, and may be copy-pasted between environments. The `private_key_password` protects the private key used to authenticate API calls to OCI — it is effectively a credential that, if compromised, grants an attacker the ability to decrypt/use the associated API signing key and impersonate the configured OCI user or service account, potentially gaining full control over cloud resources in that tenancy. Hardcoding it directly in `.tf` source puts the secret in plaintext in git history, CI logs, Terraform state backups, and any location the code is copied to — all of which are far less controlled than a proper secrets manager or environment variable. This check follows the same "no hardcoded secrets in IaC" principle applied broadly across cloud providers in Checkov.

## How Checkov evaluates this
The check is a `BaseProviderCheck` with custom `scan_provider_conf` logic:
```python
key = "private_key_password"
if key in conf.keys():
    secret = conf[key]
    if not secret:
        return CheckResult.PASSED
    return CheckResult.FAILED
else:
    return CheckResult.PASSED
```
- **PASS:** the `private_key_password` key is absent from the provider block, or present but empty/falsy (e.g., an empty string, or a reference resolving to nothing at scan time).
- **FAIL:** `private_key_password` is present and has a truthy value — i.e., an actual literal password string is set directly in the provider configuration.

## Non-compliant example
```hcl
provider "oci" {
  tenancy_ocid        = "ocid1.tenancy.oc1..aaaaaaaaexample"
  user_ocid           = "ocid1.user.oc1..aaaaaaaaexample"
  fingerprint         = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
  private_key_path    = "~/.oci/oci_api_key.pem"
  private_key_password = "SuperSecretPassphrase123!"
  region              = "us-ashburn-1"
}
```

## Remediated example
```hcl
provider "oci" {
  tenancy_ocid      = "ocid1.tenancy.oc1..aaaaaaaaexample"
  user_ocid         = "ocid1.user.oc1..aaaaaaaaexample"
  fingerprint       = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
  private_key_path  = "~/.oci/oci_api_key.pem"
  # private_key_password sourced from an environment variable instead of hardcoded here
  region            = "us-ashburn-1"
}
```
```bash
export TF_VAR_oci_private_key_password="SuperSecretPassphrase123!"
```

## Remediation steps
1. Remove the literal `private_key_password` value from the provider block.
2. Source the passphrase from an environment variable (e.g., `TF_VAR_...` combined with a `variable` block marked `sensitive = true`), a secrets manager (OCI Vault, HashiCorp Vault, AWS Secrets Manager), or your CI/CD pipeline's secret store.
3. If the private key does not require a passphrase, generate/use an unencrypted key file instead (protected by filesystem permissions and secrets-at-rest controls) rather than embedding a password to protect it.
4. Rotate the exposed key/passphrase immediately if it was ever committed to version control, since git history retains it even after removal from the current file.
5. Add a `.gitignore`/pre-commit secret-scanning check to prevent recurrence.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/oci/credentials.py)
