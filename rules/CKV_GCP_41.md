# CKV_GCP_41: Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level

## Severity
**HIGH** (score: 7.5/10)

The Service Account User/Token Creator roles let a principal impersonate service accounts and mint their tokens, effectively granting the permissions of any service account in the project and enabling straightforward privilege escalation to admin-level access.

## Summary
This check fails when a `google_project_iam_binding` or `google_project_iam_member` resource grants `roles/iam.serviceAccountUser` or `roles/iam.serviceAccountTokenCreator` at the project (rather than a specific service-account-scoped) level.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_project_iam_binding` and `google_project_iam_member`.

## Why it matters
`roles/iam.serviceAccountUser` lets a principal act as (impersonate/attach) any service account in the project — e.g., launch a Compute instance or Cloud Function running as that service account — and `roles/iam.serviceAccountTokenCreator` lets a principal mint OAuth access tokens or signed JWTs for a service account, effectively obtaining its credentials. When either role is granted at the *project* level rather than on a specific `google_service_account` resource, the grantee gains this impersonation power over **every** service account currently in the project, including ones created in the future. This is a well-known GCP privilege-escalation path: a user with only `serviceAccountUser`/`serviceAccountTokenCreator` at project scope can impersonate a highly privileged service account (e.g., one with `roles/owner`) and inherit its full permissions, bypassing whatever narrower role they were nominally granted. Scoping these roles to individual service accounts (via `google_service_account_iam_member`/`google_service_account_iam_binding` on the specific SA resource) closes this escalation path.

## How Checkov evaluates this
The check inspects the `role` attribute on the resource:
- **FAIL** if `role` is `"roles/iam.serviceAccountUser"` or `"roles/iam.serviceAccountTokenCreator"`.
- **PASS** for any other role value.
Note this check only looks at project-level IAM resources; the equivalent SA-scoped grant (`google_service_account_iam_member`) is a different, intentionally narrower resource type not covered by this check.

## Non-compliant example
```hcl
resource "google_project_iam_member" "mapping_service_account_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "group:platform-engineers@example.com"
}
```

## Remediated example
```hcl
resource "google_service_account_iam_member" "mapping_sa_user" {
  service_account_id = google_service_account.mapping_pipeline.name
  role                = "roles/iam.serviceAccountUser"
  member              = "group:platform-engineers@example.com"
}
```

## Remediation steps
1. Identify exactly which service account(s) the grantee actually needs to impersonate or attach to resources.
2. Replace the project-level `google_project_iam_member`/`google_project_iam_binding` grant of `roles/iam.serviceAccountUser` or `roles/iam.serviceAccountTokenCreator` with a `google_service_account_iam_member`/`google_service_account_iam_binding` scoped to that specific service account (`service_account_id = google_service_account.<name>.name`).
3. Re-audit any principal who currently holds this role at project scope for what service accounts they've actually used, to avoid breaking legitimate workflows when narrowing scope.
4. If truly project-wide impersonation is required (rare — e.g., a central CI system that provisions resources under many rotating SAs), document the business justification explicitly and consider compensating controls (VPC-SC, org policy constraints, additional monitoring on `GenerateAccessToken`/`SignJwt` calls).
5. No infrastructure downtime is involved — this is a pure IAM policy change, but test pipelines/deployments that rely on the broad grant before removing it, since they may start failing with permission-denied errors.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleRoleServiceAccountUser.py)
- [GCP: Service account privilege escalation and Service Account User role](https://cloud.google.com/iam/docs/service-accounts-actas)
