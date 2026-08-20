# CKV_LIN_2: Ensure SSH key set in authorized_keys

## Severity
**MEDIUM** (score: 5.0/10)

Instances left without a key-based `authorized_keys` entry fall back to password-only root access, which is materially weaker against brute-force/credential attacks but still requires a credential and is not itself a public network exposure or RCE path.

## Summary
This check ensures that a Linode Compute Instance (`linode_instance`) has at least one SSH key configured via the `authorized_keys` attribute, so the server can be accessed with key-based authentication instead of falling back to a generated or unmanaged root password.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `linode_instance`
- **Check type:** resource-configuration attribute check

## Why it matters
Linode instances that are created without an `authorized_keys` value are provisioned with only a root password (either one you supply via `root_pass` or one Linode auto-generates). Password-only root access is far more susceptible to brute-force and credential-stuffing attacks than public-key authentication, and it also means SSH credentials for the box are not managed as code / version-controlled infrastructure — there's no audit trail of which keys were authorized at provisioning time, and no easy way to guarantee only known engineers can log in. Enforcing `authorized_keys` at the Terraform level ensures every new instance boots with key-based access already configured, closing the window where only a weak or shared root password protects the host.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `authorized_keys` attribute of the `linode_instance` resource block. Checkov looks for the key to be present with **any** non-empty value (`ANY_VALUE` sentinel) — it does not validate the actual key content or format, only that the attribute is set. If `authorized_keys` is absent or empty, the check FAILS; if it is set to one or more SSH public keys, the check PASSES.

## Non-compliant example
```hcl
resource "linode_instance" "web" {
  label  = "web-server"
  image  = "linode/ubuntu22.04"
  region = "us-east"
  type   = "g6-standard-2"

  root_pass = "SuperSecretPassword123!"
  # no authorized_keys set -> relies solely on root password
}
```

## Remediated example
```hcl
resource "linode_instance" "web" {
  label  = "web-server"
  image  = "linode/ubuntu22.04"
  region = "us-east"
  type   = "g6-standard-2"

  root_pass = "SuperSecretPassword123!"

  authorized_keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... deploy@ci"
  ]
}
```

## Remediation steps
1. Add an `authorized_keys` list to every `linode_instance` resource, containing one or more public SSH keys for the operators/automation that should have access.
2. Prefer sourcing keys from a variable or a secrets/config source (e.g. `var.ssh_public_keys`) rather than hardcoding them inline, so key rotation doesn't require editing the resource definition.
3. Where feasible, also disable password authentication at the OS level (e.g. via cloud-init/`stackscript`) and avoid relying on `root_pass` for ongoing access.
4. Rotate keys periodically and remove keys for offboarded personnel by updating the Terraform configuration and re-applying.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/linode/authorized_keys.py)
- [Linode Terraform provider: linode_instance](https://registry.terraform.io/providers/linode/linode/latest/docs/resources/instance)
