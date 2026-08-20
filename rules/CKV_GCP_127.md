# CKV_GCP_127: Ensure Integrity Monitoring for Shielded Vertex AI Notebook Instances is Enabled

## Severity
**LOW** (score: 2.0/10)

Disabling integrity monitoring removes the mechanism that detects unauthorized changes to a Shielded VM's boot integrity, weakening detection of compromise rather than directly exposing the instance.

## Summary
This check fails when a `google_notebooks_instance` (Vertex AI Workbench notebook) has `enable_integrity_monitoring` explicitly set to `false` in its `shielded_instance_config`, meaning boot-time and runtime integrity of the VM is not being continuously verified.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_instance`
- **Check type:** resource (negative value check)

## Why it matters
Integrity Monitoring is a Shielded VM feature that continuously compares the VM's boot measurements (via the vTPM — see CKV_GCP_126) against a known-good baseline taken at instance launch, and reports any discrepancies to Cloud Monitoring/Logging as an actionable signal. Without it, even if Secure Boot and vTPM are enabled, tampering with the boot chain, kernel, or drivers of a compromised notebook VM would not generate any alert — the compromise could persist silently. For Vertex AI notebook instances specifically, which often hold access to training data, trained model artifacts, and service account credentials tied to ML pipelines, an undetected rootkit-level compromise could be used to exfiltrate proprietary models/data or pivot to other GCP resources the notebook's service account can reach, all without triggering any detection signal.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`:
- **Inspected key:** `shielded_instance_config/[0]/enable_integrity_monitoring`
- **Forbidden values:** `[False]`
- **FAIL** if `enable_integrity_monitoring` is explicitly set to `false`.
- **PASS** if it is `true`, or if the attribute/block is entirely absent (this negative-value check only flags an explicit `false`; it does not verify the effective/default value applied by the provider or API when unset).

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
    enable_vtpm                = true
    enable_integrity_monitoring = false
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
    enable_vtpm                 = true
    enable_integrity_monitoring = true   # <-- changed from false
    enable_secure_boot           = true
  }
}
```

## Remediation steps
1. Set `enable_integrity_monitoring = true` inside `shielded_instance_config` on every `google_notebooks_instance`.
2. Ensure `enable_vtpm = true` is also set (see CKV_GCP_127's companion check, CKV_GCP_126), since integrity monitoring depends on the vTPM measurements to have a baseline to compare against.
3. After enabling, configure alerting on the "Instance Integrity" findings surfaced in Cloud Monitoring/Security Command Center so integrity violations are actually acted upon, not just logged silently.
4. Like the vTPM setting, this is typically configured at instance creation; changing it on a live notebook instance may force recreation — schedule a maintenance window and back up notebook state beforehand.
5. Verify the base VM image (e.g. Deep Learning VM images) supports Shielded VM integrity monitoring; older or heavily customized images may need to be rebuilt.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/VertexAINotebookEnsureIntegrityMonitoring.py)
- [Google Cloud Shielded VM — Integrity Monitoring documentation](https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring)
