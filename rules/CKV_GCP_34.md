# CKV_GCP_34: Ensure that no instance in the project overrides the project setting for enabling OSLogin

## Severity
**MEDIUM** (score: 5.0/10)

An instance-level override that disables OS Login undermines the project-wide access control policy for that specific VM, weakening centralized key management and revocation for it even though exploitation still requires a separate SSH key foothold.

## Summary
This check fails when an individual GCE instance sets `metadata.enable-oslogin = false`, overriding the project-wide OS Login setting and reverting that specific instance to metadata/SSH-key-based access.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_compute_instance`, `google_compute_instance_from_template`, and `google_compute_instance_template`.

## Why it matters
Even when OS Login is correctly enabled at the project level (CKV_GCP_33), GCP allows any individual instance to opt out by setting `enable-oslogin = false` in its own metadata, which takes precedence over the project setting. This creates an inconsistent security posture: an organization may believe all SSH access is centrally governed via IAM and audited, while one or more instances have quietly fallen back to static SSH keys with no centralized revocation or audit trail. This is a common way security controls silently regress — a developer troubleshooting SSH access disables OS Login "temporarily" on one box and never reverts it, leaving a persistent gap that bypasses the org's access-control and logging story.

## How Checkov evaluates this
This is a "negative value" check on `metadata[0]["enable-oslogin"]`:
- **FAIL** if the value is `False` (i.e., the instance explicitly disables OS Login).
- **PASS** if the key is absent (inherits the project setting) or set to a truthy value.
- For `google_compute_instance_from_template`: if `metadata` is missing entirely, or present without an `enable-oslogin` key, the result is **UNKNOWN** since the effective setting depends on the source template.

## Non-compliant example
```hcl
resource "google_compute_instance" "legacy_db" {
  name         = "legacy-db"
  machine_type = "n1-standard-2"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  metadata = {
    enable-oslogin = false
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "legacy_db" {
  name         = "legacy-db"
  machine_type = "n1-standard-2"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  # No enable-oslogin override -> inherits the project-level setting (should be TRUE)
  metadata = {}
}
```

## Remediation steps
1. Remove any `enable-oslogin = false` (or `"FALSE"`) entry from instance/template metadata so the instance inherits the project-level policy.
2. If a specific workload genuinely needs to bypass OS Login (e.g., an appliance image incompatible with it), document the exception explicitly and consider isolating that instance in its own project with compensating controls (e.g., OS Login-independent MFA, tightly scoped firewall rules, session recording).
3. Audit existing instances for this override with `gcloud compute instances describe <name> --format="value(metadata)"` or a Checkov scan, since these overrides are easy to introduce accidentally during troubleshooting and easy to miss afterward.
4. This is a metadata-only change; it does not require instance recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeInstanceOSLogin.py)
- [GCP: Manage OS Login](https://cloud.google.com/compute/docs/oslogin/set-up-oslogin)
