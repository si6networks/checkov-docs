# CKV_GCP_46: Ensure Default Service account is not used at a project level

## Severity
**HIGH** (score: 7.5/10)

Binding IAM roles to the default Compute/App Engine service account at the project level extends that already broadly-scoped, often widely-held identity's privileges further, increasing the impact of any single VM or workload compromise across the project.

## Summary
This check fails when a `google_project_iam_member` or `google_project_iam_binding` resource grants a role to the project's default Compute Engine or App Engine service account, rather than to a purpose-built service account.

## Applicability
Terraform only. Applies to `google_project_iam_member` and `google_project_iam_binding`.

**Note on source:** Checkov implements this as `GoogleProjectMemberDefaultServiceAccount`, a thin subclass of the shared `AbsGoogleIAMMemberDefaultServiceAccount` base class. That abstract base's implementation was not included in the extracted source set for this doc; based on the class hierarchy and the default-service-account detection pattern used elsewhere in Checkov's GCP checks (see CKV_GCP_31, which matches the default Compute Engine service account email against the regex `\d+-compute@developer\.gserviceaccount\.com`), this check is understood to inspect the `member` field for that same default-service-account pattern (and/or the App Engine default `PROJECT_ID@appspot.gserviceaccount.com`) and fail when any role is granted to it.

## Why it matters
The default Compute Engine (`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) and App Engine (`PROJECT_ID@appspot.gserviceaccount.com`) service accounts are auto-created by GCP and, historically, auto-attached with broad `roles/editor` permissions on many workloads unless explicitly restricted. Because these accounts are shared by default across every resource that doesn't specify its own service account, granting them additional IAM roles compounds an already broad, implicitly-shared identity: any workload using the default SA — potentially several unrelated services across the project — inherits every role ever granted to it, and a compromise of any one of those workloads exposes the combined permissions of all of them. Purpose-built, per-workload service accounts (least privilege, one identity per function) let you scope permissions tightly and reason about blast radius per-service; continuing to layer permissions onto the shared default SA undermines that separation entirely and is a frequent source of accidental over-permissioning.

## How Checkov evaluates this
Based on the check's structure (inherited from `AbsGoogleIAMMemberDefaultServiceAccount`), the check inspects the `member` attribute of the project IAM resource, matching it against the default service account email pattern(s), and fails when a role is granted to that default identity regardless of which role. Grants to any other (non-default) service account, user, or group **PASS**.

## Non-compliant example
```hcl
resource "google_project_iam_member" "compute_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:123456789012-compute@developer.gserviceaccount.com"
}
```

## Remediated example
```hcl
resource "google_service_account" "data_pipeline" {
  account_id   = "data-pipeline-sa"
  display_name = "Data pipeline service account"
}

resource "google_project_iam_member" "pipeline_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.data_pipeline.email}"
}
```

## Remediation steps
1. Create a dedicated `google_service_account` for the workload currently relying on the default Compute/App Engine service account.
2. Re-point the `google_project_iam_member`/`google_project_iam_binding` grant to reference the new dedicated service account's email instead of the default SA.
3. Update the compute resource (instance, Cloud Function, Cloud Run service, etc.) that was using the default SA to explicitly reference the new dedicated service account.
4. Audit all other IAM bindings against the default SA in the affected projects (`prod` and `dev` environments here) — since the default SA is shared, there may be several roles layered onto it that each need to be moved to appropriately scoped dedicated accounts.
5. Test thoroughly in `dev` before `prod`: since the default SA is often used implicitly by several resources, removing roles from it can break workloads that were silently depending on those permissions without an explicit service-account assignment.
6. This is a pure IAM/configuration change; the primary risk is breakage from resources still implicitly depending on the default SA's now-removed permissions, not infrastructure downtime per se.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleProjectMemberDefaultServiceAccount.py)
- [GCP: Default service accounts](https://cloud.google.com/iam/docs/service-account-types#default)
