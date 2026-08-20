# CKV_GCP_32: Ensure 'Block Project-wide SSH keys' is enabled for VM instances

## Severity
**HIGH** (score: 7.5/10)

Leaving project-wide SSH keys unblocked means any key added to project metadata grants SSH access to every instance in the project, so a single leaked or overly-broad project-level key compromises the whole fleet rather than one host.

## Summary
This check requires that a GCE instance's `metadata.block-project-ssh-keys` value be set to `true`, preventing the VM from trusting any SSH public key stored at the project level.

## Applicability
Terraform only. Applies to `google_compute_instance`, `google_compute_instance_from_template`, and `google_compute_instance_template`.

## Why it matters
GCP projects can hold SSH keys at the project level (`gcloud compute project-info add-metadata --metadata ssh-keys=...`), and by default every instance in the project trusts those keys for SSH login in addition to any instance-specific keys. This means anyone who can add an SSH key to the *project* metadata — which may be a different, broader set of principals than those who manage a specific VM — gains SSH access to *every* instance in the project that hasn't opted out. This significantly widens the blast radius of a compromised IAM principal or CI credential with `compute.projects.setCommonInstanceMetadata` permission: a single mistake or leaked credential at the project level can grant remote shell access across an entire fleet of VMs, including ones the attacker never directly targeted. Enabling "Block Project-wide SSH keys" scopes trusted keys to the instance's own metadata only.

## How Checkov evaluates this
The check inspects `metadata.block-project-ssh-keys`:
- **PASS** if the value is any of `True`, `"true"`, `"True"`, `"TRUE"` (GCP/Terraform tolerate multiple boolean-ish representations).
- **FAIL** if the key is absent or set to a falsy value.
- For `google_compute_instance_from_template`: if `metadata` is absent, or `metadata` is present but doesn't contain `block-project-ssh-keys`, the result is **UNKNOWN** (the effective value depends on the referenced template, which Checkov can't resolve).

## Non-compliant example
```hcl
resource "google_compute_instance" "web" {
  name         = "web-01"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  metadata = {
    ssh-keys = "deploy:${file("~/.ssh/deploy.pub")}"
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "web" {
  name         = "web-01"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  metadata = {
    ssh-keys                 = "deploy:${file("~/.ssh/deploy.pub")}"
    block-project-ssh-keys   = "true"
  }
}
```

## Remediation steps
1. Add `block-project-ssh-keys = "true"` to the `metadata` map on every `google_compute_instance` / `google_compute_instance_template` resource.
2. If instances are created via `google_compute_instance_from_template`, set the flag on the underlying template, since the per-instance resource can't override it in a way Checkov (or GCP) will reliably apply otherwise.
3. Prefer OS Login (see CKV_GCP_33/CKV_GCP_34) over managing SSH keys in metadata at all — it ties SSH access to IAM identity and supports 2FA/audit logging.
4. After enabling this flag, confirm any project-level SSH keys previously relied on for break-glass access are re-added per-instance if still needed, to avoid an unexpected access outage.
5. This change does not require instance replacement — metadata updates apply without recreating the VM.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeBlockProjectSSH.py)
- [GCP: Restricting SSH keys from project metadata](https://cloud.google.com/compute/docs/connect/restrict-ssh-keys)
