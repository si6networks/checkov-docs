# CKV_OPENSTACK_1: Ensure no hard coded OpenStack password, token, or application_credential_secret exists in provider
## Severity
**LOW** (score: 2.0/10)

Hardcoded OpenStack password, token, or application_credential_secret values in the provider block expose cloud-admin-equivalent credentials directly in source/state, enabling full account or infrastructure takeover if the code is leaked or shared.

## Summary
This check flags Terraform `openstack` provider blocks that contain a literal `password`, `token`, or `application_credential_secret` value instead of sourcing those credentials from a secret manager or environment variable.

## Applicability
Terraform, `provider "openstack"` blocks (provider-level check, not a resource).

## Why it matters
The OpenStack Terraform provider authenticates using one of several credential types: username/password, a Keystone token, or application credentials (`application_credential_id` + `application_credential_secret`). Any of these hardcoded directly into a `.tf` file becomes:

- Committed to version control history permanently, even if later removed (git history retains the secret).
- Visible to anyone with read access to the repository, including CI logs, code review tools, and forks.
- A direct path to full OpenStack tenant/project compromise — these credentials typically grant broad control over compute instances, networking, storage, and security groups within the project.
- Not rotatable without a code change and redeploy, encouraging long-lived, rarely-rotated credentials.

Since Terraform state files and plan output may also echo these values, a hardcoded secret in source multiplies the number of places the secret leaks to.

## How Checkov evaluates this
The check (`OpenstackCredentials`, a `BaseProviderCheck`) inspects the parsed provider configuration dict for the `openstack` provider:

- **FAIL** if `password` is present and set.
- **FAIL** if `token` is present and set.
- **FAIL** if `application_credential_secret` is present and set.
- **PASS** if none of these three attributes are set in the provider block (implying credentials are supplied through environment variables like `OS_PASSWORD`, `OS_TOKEN`, `OS_APPLICATION_CREDENTIAL_SECRET`, or an external `clouds.yaml`/vault mechanism instead).

Any of the three attributes present with a non-empty value trips a FAIL independently — the check does not require all three to look for a violation.

## Non-compliant example
```hcl
provider "openstack" {
  user_name   = "admin"
  tenant_name = "admin"
  password    = "S3cr3tP@ssw0rd!"   # hardcoded credential
  auth_url    = "https://openstack.example.com:5000/v3"
}
```

## Remediated example
```hcl
provider "openstack" {
  user_name   = "admin"
  tenant_name = "admin"
  # password intentionally omitted; supplied via OS_PASSWORD env var
  auth_url    = "https://openstack.example.com:5000/v3"
}
```
```bash
# in CI/shell, not committed to source:
export OS_PASSWORD="S3cr3tP@ssw0rd!"
```

## Remediation steps
1. Remove `password`, `token`, and `application_credential_secret` from any `provider "openstack"` block.
2. Rely on the standard OpenStack environment variables (`OS_PASSWORD`, `OS_TOKEN`, `OS_APPLICATION_CREDENTIAL_SECRET`, etc.) sourced from an `openrc` file that is never committed, or inject them via your CI/CD secret store.
3. Prefer application credentials over user password auth where possible — they can be scoped and revoked independently of the user account.
4. If a secret was ever committed, rotate/revoke it in OpenStack (Keystone) immediately and scrub git history (e.g. with `git filter-repo` or BFG) since removal alone doesn't erase history.
5. Consider using a secrets manager (Vault, AWS Secrets Manager, etc.) integrated with Terraform via data sources instead of plain environment variables for stronger auditability.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/provider/openstack/credentials.py
- Terraform OpenStack provider configuration reference: https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs
