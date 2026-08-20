# CKV_OPENSTACK_4: Ensure that instance does not use basic credentials
## Severity
**LOW** (score: 2.0/10)

Setting a hardcoded admin_pass on an openstack_compute_instance_v2 resource embeds a static root/administrator credential in Terraform code and state, creating an easily-discovered path to full instance compromise.

## Summary
This check ensures OpenStack Nova compute instances do not set a hardcoded `admin_pass` value, which would embed a plain-text administrator password for the instance directly in Terraform source.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `openstack_compute_instance_v2`.

## Why it matters
`admin_pass` sets the initial administrator/root password for a newly created compute instance. Setting it explicitly in Terraform configuration means:

- The password is stored in plain text in the `.tf` file and in Terraform state, and is retained in version control history indefinitely even after later removal.
- Anyone with read access to the repo, CI logs, or the Terraform state backend can recover full administrative access to the instance.
- It bypasses cloud-init/metadata-service-based secure bootstrapping (e.g., injected SSH keys, one-time passwords set via `cloud-init` and rotated on first boot), instead fixing a long-lived, static credential known to everyone who can read the code.
- If the same password is reused across instances (a common anti-pattern when hardcoded in a module), a single leak compromises every instance built from that module.

The safe default is to omit `admin_pass` (letting OpenStack generate/inject credentials via key pairs or metadata) rather than fixing a static known password in source.

## How Checkov evaluates this
The check (`ComputeInstanceAdminPassword`, a `BaseResourceNegativeValueCheck` with `ANY_VALUE` as the forbidden value) inspects `openstack_compute_instance_v2` resources:

- Reads the `admin_pass` attribute.
- **FAIL** if `admin_pass` is set to any non-empty value (the forbidden value is `ANY_VALUE`, meaning literally any value present triggers a fail).
- **PASS** if `admin_pass` is absent, or explicitly set to an empty string — the check's `missing_attribute_result` is `PASSED`, so omitting the attribute entirely is compliant.

## Non-compliant example
```hcl
resource "openstack_compute_instance_v2" "web" {
  name        = "web-server"
  image_name  = "ubuntu-22.04"
  flavor_name = "m1.small"
  key_pair    = openstack_compute_keypair_v2.deployer.name
  admin_pass  = "SuperSecret123!"   # hardcoded plain-text password

  network {
    name = "internal"
  }
}
```

## Remediated example
```hcl
resource "openstack_compute_instance_v2" "web" {
  name        = "web-server"
  image_name  = "ubuntu-22.04"
  flavor_name = "m1.small"
  key_pair    = openstack_compute_keypair_v2.deployer.name
  # admin_pass omitted entirely; access is via injected SSH key pair instead

  network {
    name = "internal"
  }
}
```

## Remediation steps
1. Remove the `admin_pass` attribute from `openstack_compute_instance_v2` resources.
2. Rely on `key_pair` (SSH key injection) for Linux instances, or a cloud-init/user_data script that generates and securely delivers a one-time credential.
3. For Windows instances, use the metadata service's Windows password retrieval mechanism (encrypted with the instance's key pair) rather than a static `admin_pass`.
4. If any instance was ever deployed with a hardcoded password, rotate/change that password on the running instance and purge the value from Terraform state and git history.
5. Enforce this via CI (Checkov) so `admin_pass` can never be reintroduced in a future PR.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/openstack/ComputeInstanceAdminPassword.py
- Terraform OpenStack `openstack_compute_instance_v2` reference: https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/compute_instance_v2
