# CKV_GCP_49: Ensure roles do not impersonate or manage Service Accounts used at project level

## Severity
**LOW** (score: 2.0/10)

Granting a role that can impersonate or manage other service accounts at project scope enables privilege escalation, since holding that role effectively grants the permissions of any service account it can act as.

## Summary
This check fails when a `google_project_iam_member` or `google_project_iam_binding` resource grants a project-level role that allows impersonating, creating, or managing service accounts (or other high-privilege service-agent/admin roles), since such roles let a principal act as, or escalate to, other identities in the project.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource types:** `google_project_iam_member`, `google_project_iam_binding`
- **Check type:** resource check

## Why it matters
Roles such as `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`, `roles/owner`, `roles/editor`, and numerous `*.serviceAgent` roles allow a principal to impersonate a service account or otherwise assume its permissions (e.g., minting OAuth tokens, signing JWTs, or attaching the SA to new resources). Granting these at the project level is a classic **privilege-escalation vector**: a principal with `serviceAccountTokenCreator` on a project can impersonate any service account in that project — including ones with far more privilege than the grantee's own role — effectively bypassing the intended IAM boundary. Because the binding is scoped to the whole project rather than a single named service account, the risk multiplies across every current and future SA in the project.

## How Checkov evaluates this
The check (`GoogleProjectImpersonationRoles`, via base class `AbsGoogleImpersonationRoles`) reads the `role` attribute of the resource and compares it against a hard-coded denylist of roles known to permit impersonation or service-account/service-agent management (e.g. `roles/owner`, `roles/editor`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`, `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.workloadIdentityUser`, and dozens of `*.serviceAgent` / admin roles for services like Dataflow, Cloud Build, Cloud Functions, GKE, etc.).

- **FAIL** if `role` is in the `IMPERSONATION_ROLES` list.
- **PASS** otherwise.

## Non-compliant example
```hcl
resource "google_project_iam_member" "project" {
  project = "my-gcp-project"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "user:developer@example.com"
}
```

## Remediated example
```hcl
# Scope impersonation to a single named service account instead of the whole project
resource "google_service_account_iam_member" "sa_token_creator" {
  service_account_id = google_service_account.deploy.name
  role                = "roles/iam.serviceAccountTokenCreator"
  member              = "user:developer@example.com"
}
```

## Remediation steps
1. Identify why the impersonation/admin role is granted at project scope — usually it should be scoped to one specific service account instead.
2. Replace the `google_project_iam_member`/`google_project_iam_binding` with a `google_service_account_iam_member`/`google_service_account_iam_binding` bound to only the specific service account(s) that need to be impersonated.
3. If a genuinely project-wide grant is required (e.g., a CI/CD platform), restrict the principal to a tightly scoped group and add compensating controls (VPC-SC, audit alerting on `GenerateAccessToken`/`SignJwt` calls, org policy `constraints/iam.disableServiceAccountKeyCreation`).
4. Re-run `terraform plan` and Checkov after remediation to confirm the binding no longer matches the denylisted role.
5. Consider adopting Workload Identity Federation to eliminate the need for direct service-account impersonation entirely.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleProjectImpersonationRole.py)
- [GCP: Best practices for using service accounts](https://cloud.google.com/iam/docs/best-practices-service-accounts)
- [GCP: IAM permissions reference](https://cloud.google.com/iam/docs/permissions-reference)
