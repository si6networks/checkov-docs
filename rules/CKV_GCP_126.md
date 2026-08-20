# CKV_GCP_126: Ensure Vertex AI Notebook instances are launched with Shielded VM enabled

## Severity
**LOW** (score: 2.0/10)

Disabling Shielded VM's virtual TPM removes a defense-in-depth boot-integrity control on the notebook instance, raising the risk of undetected persistence via rootkits/bootkits rather than opening a direct network-exposure path.

## Summary
This check fails when a `google_notebooks_instance` (Vertex AI Workbench notebook) does not have the Shielded VM virtual TPM (`enable_vtpm`) enabled in its `shielded_instance_config`, leaving the notebook VM without boot-integrity protections.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_instance`
- **Check type:** resource (negative value check)

## Why it matters
Shielded VM features (Secure Boot, virtual Trusted Platform Module (vTPM), and Integrity Monitoring) protect against rootkits and bootkits — malware that persists by tampering with the boot loader, kernel, or drivers before the OS's own security controls load. Vertex AI Notebook instances run as full Compute Engine VMs and are often granted broad IAM roles and access to sensitive datasets, models, and service account credentials used for training/inference pipelines. Without a vTPM, the VM cannot generate or verify cryptographic measurements of its boot chain, meaning tampering with the boot process (e.g. via a compromised custom image, a malicious extension, or an attacker with temporary access to the underlying disk) would not be detectable or preventable at the platform level. Enabling `enable_vtpm` is a prerequisite for the other Shielded VM protections (e.g. Secure Boot, Integrity Monitoring — see CKV_GCP_127) to function.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`:
- **Inspected key:** `shielded_instance_config/[0]/enable_vtpm`
- **Forbidden values:** `[False]`
- **FAIL** if `enable_vtpm` is explicitly set to `false`.
- **PASS** if `enable_vtpm` is `true`, or if the `shielded_instance_config` block / `enable_vtpm` attribute is absent (negative-value checks only fail on an explicit forbidden value being present, not on the attribute being unset — check your provider's default carefully, since relying on omission does not guarantee the setting is actually enabled in the deployed resource).

## Non-compliant example
```hcl
resource "google_notebooks_instance" "ml_notebook" {
  name         = "ml-research-notebook"
  location     = "us-central1-a"
  machine_type = "n1-standard-4"

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }

  shielded_instance_config {
    enable_vtpm = false
  }
}
```

## Remediated example
```hcl
resource "google_notebooks_instance" "ml_notebook" {
  name         = "ml-research-notebook"
  location     = "us-central1-a"
  machine_type = "n1-standard-4"

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }

  shielded_instance_config {
    enable_vtpm                = true   # <-- changed from false
    enable_secure_boot          = true
    enable_integrity_monitoring = true
  }
}
```

## Remediation steps
1. Add (or correct) a `shielded_instance_config` block on the `google_notebooks_instance` resource with `enable_vtpm = true`.
2. While updating this block, also set `enable_integrity_monitoring = true` (see CKV_GCP_127) and `enable_secure_boot = true` for full Shielded VM protection.
3. Confirm the underlying VM image supports Shielded VM (most current Deep Learning VM / Vertex AI Workbench images do); custom images built from older bases may need to be rebuilt with Shielded VM support.
4. This setting typically must be configured at instance creation; changing it on an existing running notebook instance may require recreating the instance — plan for a maintenance window and back up any local notebook state/data first.
5. Apply this configuration consistently across all Vertex AI Workbench notebooks, since a single unshielded notebook with access to models/data/service-account credentials can undermine the security posture of the broader ML pipeline.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleVertexAINotebookShieldedVM.py)
- [Google Cloud Shielded VM documentation](https://cloud.google.com/security/shielded-cloud/shielded-vm)
