# CKV_GCP_39: Ensure Compute instances are launched with Shielded VM enabled

## Severity
**HIGH** (score: 7.5/10)

Shielded VM protections (secure boot, vTPM, integrity monitoring) defend against boot-level rootkits and firmware tampering; omitting them leaves instances vulnerable to persistent, hard-to-detect compromise below the OS security boundary.

## Summary
This check requires a GCE instance's `shielded_instance_config` block to have both `enable_vtpm` and `enable_integrity_monitoring` set to `true`, enabling Shielded VM protections against boot- and kernel-level rootkits.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_compute_instance`, `google_compute_instance_template`, and `google_compute_instance_from_template`.

## Why it matters
Shielded VM provides three protections — Secure Boot, virtual TPM (vTPM), and integrity monitoring — designed to detect and prevent boot-level and kernel-level malware such as bootkits and rootkits that operate below the OS and are invisible to normal endpoint security tools. The vTPM enables measured boot: it cryptographically records the boot chain (firmware, bootloader, kernel, drivers) so tampering can be detected. Integrity monitoring compares each subsequent boot's measurements to a trusted baseline and alerts on unexpected changes (e.g., an attacker who has modified the boot chain to persist across reboots or evade detection). Without these enabled, a sufficiently privileged attacker (e.g., one who gains root or hypervisor-adjacent access) can install a persistent, hard-to-detect bootkit that survives OS reinstalls and evades traditional file-integrity/antivirus tooling, since those tools run *after* the compromised boot chain has already executed.

## How Checkov evaluates this
The check inspects the `shielded_instance_config` block:
- **FAIL** if `shielded_instance_config` is absent entirely.
- **FAIL** if present but `enable_vtpm` is explicitly set to a falsy value.
- **FAIL** if present but `enable_integrity_monitoring` is explicitly set to a falsy value.
- **PASS** if `shielded_instance_config` is present and neither of those two fields is falsy.
- For `google_compute_instance_from_template`: **UNKNOWN** if `shielded_instance_config` is absent, since the effective config would come from the referenced template.
- Note: Shielded VM requires a compatible boot image; not all images support it.

## Non-compliant example
```hcl
resource "google_compute_instance" "ci_runner" {
  name         = "ci-runner"
  machine_type = "n2-standard-4"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "ci_runner" {
  name         = "ci-runner"
  machine_type = "n2-standard-4"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
```

## Remediation steps
1. Add a `shielded_instance_config` block with `enable_vtpm = true` and `enable_integrity_monitoring = true` (also enable `enable_secure_boot = true` where the workload/kernel modules support it — Checkov doesn't require it but Google recommends all three together).
2. Confirm the boot image supports Shielded VM (most current public images, including Debian/Ubuntu/COS/Windows, do — see GCP's shielded-images list); custom images may need re-import with Shielded VM support enabled.
3. Apply the same block to `google_compute_instance_template` resources used by managed instance groups (e.g., the CI runner pool), so autoscaled instances inherit the protection.
4. Changing `shielded_instance_config` on an existing instance requires stopping the instance (Terraform will show an in-place update requiring stop, or in some cases forces replacement depending on provider version).
5. For GKE node pools, Shielded GKE Nodes is configured separately at the node pool level, not via this resource.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeShieldedVM.py)
- [GCP: Shielded VM overview](https://cloud.google.com/security/shielded-cloud/shielded-vm)
- [GCP: Images supporting Shielded VM](https://cloud.google.com/compute/docs/images#shielded-images)
