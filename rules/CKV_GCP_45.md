# CKV_GCP_45: Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level

## Severity
**HIGH** (score: 7.5/10)

Granting organization-wide service-account impersonation/management rights allows escalation to admin control over every project in the entire organization, representing the broadest possible privilege-escalation blast radius.

## Summary
This check fails when a `google_organization_iam_member` or `google_organization_iam_binding` resource grants a role that lets the bound principal impersonate or manage all service accounts across the entire organization.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_organization_iam_member` and `google_organization_iam_binding`.

**Note on source:** Checkov implements this as `GoogleOrgImpersonationRoles`, a thin subclass of the shared `AbsGoogleImpersonationRoles` base class. The abstract base class's implementation was not included in the extracted source set for this doc; the description of its evaluation logic below is inferred from the check's name/class hierarchy and the closely related project-level check CKV_GCP_41, which enumerates `roles/iam.serviceAccountUser` and `roles/iam.serviceAccountTokenCreator` as the impersonation-enabling roles it targets.

## Why it matters
This is the most severe scope at which an impersonation-capable role can be granted: organization-level IAM bindings apply to every folder and every project across the entire org, present and future. A principal granted `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, or a similarly broad service-account-admin role at the organization level can impersonate or manage literally any service account anywhere in the organization, including highly privileged automation/deployment service accounts in any business unit. Combined with GCP's documented service-account impersonation privilege-escalation chain, a single compromised or over-trusted credential holding this org-level grant effectively has a path to full organizational compromise. Because org-level policy changes are rare and often set up once during initial GCP onboarding, these grants are also prone to being forgotten and never revisited even as the organization scales.

## How Checkov evaluates this
Based on the check's structure (inherited from `AbsGoogleImpersonationRoles`) and its sibling checks, the check inspects the `role` attribute of the organization IAM resource and fails when it matches one of the roles that permit impersonating or administering service accounts broadly (e.g. `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountAdmin`). Any other role **PASSES**.

## Non-compliant example
```hcl
resource "google_organization_iam_member" "org_sa_user" {
  org_id = "123456789012"
  role   = "roles/iam.serviceAccountUser"
  member = "serviceAccount:central-ci@platform-project.iam.gserviceaccount.com"
}
```

## Remediated example
```hcl
resource "google_project_iam_member" "scoped_sa_user" {
  project = "platform-project"
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:central-ci@platform-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Determine the actual minimum scope needed — this should almost never genuinely require organization-wide impersonation rights.
2. Move the grant to the narrowest resource that satisfies the use case: a specific `google_service_account_iam_member` on one SA, or at worst a single project's `google_project_iam_member`.
3. Run `gcloud organizations get-iam-policy <org-id>` to audit all current organization-level bindings for these roles, since they're set up rarely and easily forgotten.
4. If a central platform/automation team legitimately needs broad cross-project impersonation, formalize it as a documented, monitored exception with alerting on `GenerateAccessToken`/`SignJwt` API calls rather than a blanket org-level grant.
5. Pure IAM change, no infrastructure downtime — but verify no legitimate cross-org automation depends on the existing grant before removing it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleOrgImpersonationRole.py)
- [GCP: Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
