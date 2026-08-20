# CKV_GCP_47: Ensure default service account is not used at an organization level

## Severity
**HIGH** (score: 7.5/10)

Using the default service account at the organization level compounds the over-privileged, widely-shared nature of that identity across every project in the org, so its compromise has an organization-wide privilege-escalation impact.

## Summary
This check fails when a `google_organization_iam_member` or `google_organization_iam_binding` resource grants a role to a project's default Compute Engine or App Engine service account at the organization level.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_organization_iam_member` and `google_organization_iam_binding`.

**Note on source:** Checkov implements this as `GoogleOrgMemberDefaultServiceAccount`, a thin subclass of the shared `AbsGoogleIAMMemberDefaultServiceAccount` base class (the same base class used by CKV_GCP_46 at project scope). That abstract base's implementation was not included in the extracted source set for this doc; based on the class hierarchy and the default-service-account detection pattern used elsewhere in Checkov's GCP checks (see CKV_GCP_31's regex `\d+-compute@developer\.gserviceaccount\.com` for the default Compute Engine SA), this check is understood to inspect the `member` field for that same default-service-account pattern and fail when any role is granted to it at organization scope.

## Why it matters
Granting any role to a default service account at the *organization* level is the most severe form of this misconfiguration: the default Compute Engine/App Engine service account is already an implicitly shared identity attached to workloads that don't specify their own SA, and elevating its permissions at the organization level means every project across the entire org that relies on that pattern inherits the additional access — while every workload that happens to run under a matching default SA anywhere in the org effectively gains the same organization-wide privilege. Combined with the fact that default SAs are commonly used carelessly (developers often don't bother creating a dedicated SA for quick prototypes), an org-level grant to a default SA can silently hand broad, organization-spanning permissions to a large and poorly-tracked set of workloads, making it very difficult to reason about or audit who effectively holds that access.

## How Checkov evaluates this
Based on the check's structure (inherited from `AbsGoogleIAMMemberDefaultServiceAccount`), the check inspects the `member` attribute of the organization IAM resource, matching it against the default service account email pattern(s), and fails when a role is granted to that default identity regardless of which role. Grants to any other (non-default) service account, user, or group **PASS**.

## Non-compliant example
```hcl
resource "google_organization_iam_member" "org_default_sa_viewer" {
  org_id = "123456789012"
  role   = "roles/viewer"
  member = "serviceAccount:987654321098-compute@developer.gserviceaccount.com"
}
```

## Remediated example
```hcl
resource "google_service_account" "org_reporting" {
  project      = "central-platform-project"
  account_id   = "org-reporting-sa"
  display_name = "Organization reporting service account"
}

resource "google_organization_iam_member" "org_reporting_viewer" {
  org_id = "123456789012"
  role   = "roles/viewer"
  member = "serviceAccount:${google_service_account.org_reporting.email}"
}
```

## Remediation steps
1. Create a dedicated `google_service_account` for whatever workload currently needs organization-level access.
2. Re-point the `google_organization_iam_member`/`google_organization_iam_binding` grant to the dedicated service account's email instead of the default SA.
3. Update the resource/workload that was using the default SA implicitly to explicitly reference the new dedicated service account.
4. Audit `gcloud organizations get-iam-policy <org-id>` for any other bindings against default SA email patterns (`*-compute@developer.gserviceaccount.com`, `*@appspot.gserviceaccount.com`) across the org, since these are easy to introduce accidentally and easy to overlook thereafter.
5. Test in a non-production organization/folder first if possible; because org-level grants are broad and rare, removing one can have wide-reaching and hard-to-predict impact — verify no legitimate cross-org automation depends on it before removal.
6. Pure IAM/configuration change; the main risk is functional breakage, not infrastructure downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleOrgMemberDefaultServiceAccount.py)
- [GCP: Default service accounts](https://cloud.google.com/iam/docs/service-account-types#default)
