# CKV_DIO_2: Ensure the droplet specifies an SSH key

## Severity
**MEDIUM** (score: 5.5/10)

A droplet created without an SSH key falls back to DigitalOcean emailing a randomly generated root password, a weaker and more leak-prone authentication path than key-based SSH access.

## Summary
This check requires that a DigitalOcean Droplet (`digitalocean_droplet`) resource specifies at least one SSH key via the `ssh_keys` attribute, rather than relying on a generated root password.

## Applicability
**Checkov framework(s):** `terraform`

Terraform resource type `digitalocean_droplet` (DigitalOcean provider). Specifically inspects the `ssh_keys` attribute for the presence of any value.

## Why it matters
When a DigitalOcean Droplet is created without `ssh_keys`, DigitalOcean emails a randomly-generated root password to the account owner and requires the user to change it on first login via the console — a workflow that is both operationally fragile (email delivery, manual password handling) and materially weaker than key-based authentication. Password-based root SSH access is far more susceptible to brute-force attacks, credential leakage (e.g., the initial password sitting in an email inbox or Terraform apply logs), and reuse across systems than public-key authentication. Enforcing `ssh_keys` ensures droplets boot with key-based access only, closing off a common initial-access vector for Linux servers exposed to the internet.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` as the expected value for the `ssh_keys` attribute — meaning the check simply verifies that `ssh_keys` is set to *any* non-empty value (it does not validate the specific key IDs/fingerprints). If `ssh_keys` is missing or empty, the check FAILS. If `ssh_keys` contains at least one entry, it PASSES.

## Non-compliant example
```hcl
resource "digitalocean_droplet" "web" {
  image  = "ubuntu-22-04-x64"
  name   = "web-01"
  region = "nyc3"
  size   = "s-1vcpu-1gb"
}
```

## Remediated example
```hcl
resource "digitalocean_ssh_key" "default" {
  name       = "deploy-key"
  public_key = file("~/.ssh/id_ed25519.pub")
}

resource "digitalocean_droplet" "web" {
  image    = "ubuntu-22-04-x64"
  name     = "web-01"
  region   = "nyc3"
  size     = "s-1vcpu-1gb"
  ssh_keys = [digitalocean_ssh_key.default.fingerprint]
}
```

## Remediation steps
1. Upload the intended public SSH key to DigitalOcean, either as a `digitalocean_ssh_key` Terraform resource or manually via the control panel/API, ahead of droplet creation.
2. Add the `ssh_keys` attribute to the `digitalocean_droplet` resource, referencing the key's fingerprint or ID (a list, since multiple keys can be supplied).
3. Note this generally must be set at creation time — changing `ssh_keys` on an existing droplet in Terraform typically requires recreation (check current provider behavior; some providers mark this attribute `ForceNew`).
4. Disable password authentication for SSH at the OS level (`PasswordAuthentication no` in `sshd_config`) as defense-in-depth, in addition to supplying a key at provisioning time.
5. Re-run `terraform plan`/`checkov` to confirm the resource now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/digitalocean/DropletSSHKeys.py
- DigitalOcean Terraform provider docs: https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/droplet
