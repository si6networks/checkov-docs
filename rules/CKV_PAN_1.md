# CKV_PAN_1: Ensure no hard coded PAN-OS credentials exist in provider
## Severity
**CRITICAL** (score: 9.5/10)

Hardcoded PAN-OS api_key or password values in the Terraform provider block expose credentials that grant administrative control over the firewall's configuration, allowing full compromise of network security controls if disclosed.

## Summary
This check flags Terraform `panos` provider blocks that contain a hardcoded `password` or an `api_key` that matches a recognizable PAN-OS API key pattern, instead of sourcing those credentials externally.

## Applicability
Terraform, `provider "panos"` blocks (provider-level check for the Palo Alto Networks PAN-OS Terraform provider).

## Why it matters
The `panos` provider authenticates to a Palo Alto Networks firewall or Panorama management plane using either a username/password pair or a generated API key. Either credential, if hardcoded in Terraform source:

- Grants direct administrative access to the firewall/Panorama management interface — compromise of this credential can allow an attacker to modify security policies, disable logging, or open holes in network segmentation enforced by the device.
- Is permanently retained in git history even after later removal, and is visible to anyone with repo/CI access.
- Cannot be rotated without a code change, encouraging long-lived static credentials on a device that is itself a core security control point.
- API keys derived from admin credentials inherit whatever privilege level that admin account has, so leaking the key is equivalent to leaking full admin access to the firewall.

Because PAN-OS devices are typically the security enforcement boundary (next-gen firewall, IPS, URL filtering, etc.), credential compromise here has outsized blast radius compared to a typical application credential.

## How Checkov evaluates this
The check (`PanosCredentials`, a `BaseProviderCheck`) inspects the parsed `panos` provider configuration:

- **FAIL** if `api_key` is present and either (a) is not a string, or (b) matches the known `panos_api_key_pattern` regex used to recognize PAN-OS API key formats.
- **FAIL** if `password` is present and set to any value.
- **PASS** if neither `api_key` (matching the pattern) nor `password` is present in the provider block — implying credentials are supplied via environment variables or an external secrets mechanism instead.

## Non-compliant example
```hcl
provider "panos" {
  hostname = "firewall.example.com"
  username = "admin"
  password = "P@nosAdminPass!"   # hardcoded credential
}
```

## Remediated example
```hcl
provider "panos" {
  hostname = "firewall.example.com"
  # username/password intentionally omitted;
  # supplied via PANOS_USERNAME / PANOS_PASSWORD environment variables
}
```
```bash
# in CI/shell, not committed to source:
export PANOS_USERNAME="admin"
export PANOS_PASSWORD="P@nosAdminPass!"
```

## Remediation steps
1. Remove `password` and any literal `api_key` value from `provider "panos"` blocks.
2. Supply credentials via the provider's supported environment variables (e.g., `PANOS_USERNAME`/`PANOS_PASSWORD` or `PANOS_API_KEY`, per the provider's documentation) injected by your CI/CD secret store.
3. Prefer a dedicated automation admin account with least-privilege RBAC on the firewall rather than reusing a super-admin credential.
4. If a credential was ever committed, revoke/regenerate the PAN-OS API key or change the admin password immediately, and scrub git history.
5. Store the secret in a vault (HashiCorp Vault, AWS Secrets Manager, etc.) and inject at plan/apply time for stronger auditability and rotation support.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/panos/credentials.py
- PAN-OS Terraform provider documentation: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs
