# CKV_GCP_33: Ensure oslogin is enabled for a Project

## Severity
**MEDIUM** (score: 5.5/10)

OS Login centralizes SSH key/IAM-based access control and revocation instead of static metadata keys, so disabling it weakens access governance and audit trails but does not by itself grant unauthorized access.

## Summary
This check requires that the `enable-oslogin` project metadata key be set to `"TRUE"` on a `google_compute_project_metadata` resource, turning on OS Login for all instances in the project by default.

## Applicability
Terraform only. Applies to the `google_compute_project_metadata` resource.

## Why it matters
Without OS Login, SSH access to GCE instances is controlled by manually distributed public keys stored in instance or project metadata, with no tie to centralized IAM identity, no automatic de-provisioning when an employee leaves, and no per-user audit trail of who logged in. OS Login instead maps SSH access to Google/Cloud Identity accounts and IAM roles (`roles/compute.osLogin`, `roles/compute.osAdminLogin`), so access can be granted/revoked centrally, 2-step verification can be enforced, and login events are attributable to a specific IAM principal in Cloud Audit Logs. Leaving OS Login disabled at the project level means every instance falls back to static SSH keys, which are easy to leave stale, hard to rotate at scale, and provide no way to immediately cut off an individual's access without touching every VM.

## How Checkov evaluates this
The check reads `metadata[0]["enable-oslogin"]` and requires it to equal the string `"TRUE"`.
- **PASS**: `enable-oslogin = "TRUE"`.
- **FAIL**: the key is missing, or set to any other value (e.g. `"FALSE"`, unset, boolean `false`).

## Non-compliant example
```hcl
resource "google_compute_project_metadata" "default" {
  metadata = {
    enable-oslogin = "FALSE"
  }
}
```

## Remediated example
```hcl
resource "google_compute_project_metadata" "default" {
  metadata = {
    enable-oslogin = "TRUE"
  }
}
```

## Remediation steps
1. Define or update the `google_compute_project_metadata` resource so `metadata.enable-oslogin` is the string `"TRUE"`.
2. Ensure users who need SSH access are granted `roles/compute.osLogin` (non-admin) or `roles/compute.osAdminLogin` (sudo) via IAM, since enabling OS Login alone doesn't grant anyone access.
3. Check for per-instance overrides (see CKV_GCP_34) — an instance can still disable OS Login individually even when it's enabled at the project level.
4. If using OS Login with 2FA, also configure `roles/compute.osLoginExternalUser` or `enable-oslogin-2fa` metadata as needed for your organization's policy.
5. This is a metadata-only change and does not require instance recreation, though existing SSH sessions/keys distributed out-of-band will stop being the primary access method going forward.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeProjectOSLogin.py)
- [GCP: Manage OS Login](https://cloud.google.com/compute/docs/oslogin/set-up-oslogin)
