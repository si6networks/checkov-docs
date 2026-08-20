# CKV_GCP_44: Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level

## Severity
**HIGH** (score: 7.5/10)

Roles allowing impersonation/management of all service accounts at the folder level grant effectively unrestricted privilege escalation across every project under that folder, far exceeding the blast radius of a single-project misconfiguration.

## Summary
This check fails when a `google_folder_iam_member` or `google_folder_iam_binding` resource grants a role that lets the bound principal impersonate or manage all service accounts within that folder (e.g., broad service-account-admin/impersonation roles such as `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, or `roles/iam.serviceAccountAdmin`).

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_folder_iam_member` and `google_folder_iam_binding`.

**Note on source:** Checkov implements this as `GoogleFolderImpersonationRoles`, a thin subclass of the shared `AbsGoogleImpersonationRoles` base class (the abstract base's implementation was not included in the extracted source set for this doc, so the exact role list/regex below is inferred from the check's name, its sibling check CKV_GCP_45 which shares the same base class at organization scope, and the closely related project-level check CKV_GCP_41 which enumerates `roles/iam.serviceAccountUser` and `roles/iam.serviceAccountTokenCreator` as impersonation-enabling roles).

## Why it matters
Folder-level IAM bindings apply to every project nested under that folder, present and future. Granting an impersonation-capable role (Service Account User, Service Account Token Creator, or Service Account Admin) at the folder level means the grantee can impersonate — or fully manage — *every* service account in *every* project under that folder, including ones that don't exist yet. This is an extremely broad privilege: since service accounts commonly carry elevated permissions for automation (deployments, data pipelines, infrastructure provisioning), a principal with folder-wide impersonation rights can escalate to whatever the most-privileged service account under that folder holds — potentially organization-wide administrative control — via GCP's well-documented service-account impersonation escalation path. Scoping such roles down to a single project or, better, a single service account resource dramatically limits this exposure.

## How Checkov evaluates this
Based on the check's structure (inherited from `AbsGoogleImpersonationRoles`) and its sibling checks, the check inspects the `role` attribute of the folder IAM resource and fails when it matches one of the roles that permit impersonating or administering service accounts broadly (e.g. `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountAdmin`). Any other role **PASSES**.

## Non-compliant example
```hcl
resource "google_folder_iam_member" "eng_folder_sa_admin" {
  folder = "folders/123456789012"
  role   = "roles/iam.serviceAccountTokenCreator"
  member = "group:eng-leads@example.com"
}
```

## Remediated example
```hcl
resource "google_project_iam_member" "specific_project_sa_admin" {
  project = "eng-sandbox-project"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "group:eng-leads@example.com"
}
```

## Remediation steps
1. Identify the actual scope needed — almost certainly a single project or a single service account, not an entire folder.
2. Move the grant down to the narrowest applicable resource: prefer `google_service_account_iam_member` scoped to one service account; if that's too granular for the use case, use `google_project_iam_member` scoped to one project instead of the folder.
3. Audit existing folder-level bindings for these roles across your resource hierarchy (`gcloud resource-manager folders get-iam-policy <folder-id>`) since folder-level grants are easy to overlook and affect every child project silently.
4. If a legitimate cross-project automation use case exists (e.g., a central platform team), consider a dedicated, tightly audited service account with delegated, logged impersonation rather than a broad human/group grant at folder scope.
5. This is a pure IAM change with no infrastructure downtime; verify dependent automation still functions after narrowing scope.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleFolderImpersonationRole.py)
- [GCP: Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
