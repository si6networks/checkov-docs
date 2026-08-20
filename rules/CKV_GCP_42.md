# CKV_GCP_42: Ensure that Service Account has no Admin privileges

## Severity
**HIGH** (score: 7.5/10)

Granting a service account admin/owner-level privileges means any compromise of that account's credentials (which are often embedded in workloads) yields full administrative control over the project, a textbook wildcard-admin exposure.

## Summary
This check fails when a `google_project_iam_member` resource grants an Admin, Editor, or Owner role directly to a user-managed service account (an `*.iam.gserviceaccount.com` principal).

## Applicability
Terraform only. Applies to the `google_project_iam_member` resource.

## Why it matters
Service accounts are usually attached to running workloads (VMs, functions, CI pipelines, containers) rather than protected by human-oriented controls like interactive MFA prompts or session timeouts, and their keys/tokens are often embedded in automation. If a service account is itself granted an Admin, Editor, or Owner role at the project level, then compromising *any* workload that uses that service account's credentials — via SSRF against the instance metadata server, a leaked JSON key, a vulnerable dependency in the code it runs, or a misconfigured CI job — hands the attacker project-wide administrative control. This is disproportionate to what most service accounts should need: a workload identity should hold the narrowest set of permissions required for its specific task, so that a single compromised credential doesn't cascade into full project takeover. Because service account keys/tokens are also more commonly leaked (checked into repos, cached in logs, embedded in container images) than human credentials protected by SSO/MFA, the blast radius of over-permissioning service accounts is a disproportionately common real-world incident cause.

## How Checkov evaluates this
The check applies two regexes to the resource:
- `USER_MANAGED_SERVICE_ACCOUNT` matches `member` values ending in `@*.iam.gserviceaccount.com` (i.e., the `member` is a user-created service account, not a human user, group, or Google-managed default SA).
- `ADMIN_ROLE` matches `role` values containing `Admin`, `admin`, `editor`, or `owner` anywhere in the string (e.g. `roles/editor`, `roles/owner`, `roles/storage.admin`, `roles/iam.securityAdmin`).
- **FAIL** if both match simultaneously — i.e., a user-managed SA is bound to a role matching the admin/editor/owner pattern.
- **PASS** otherwise (e.g., the member is a human user/group, or the role is narrowly scoped like `roles/storage.objectViewer`).

## Non-compliant example
```hcl
resource "google_project_iam_member" "pipeline_admin" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:pipeline-runner@my-project.iam.gserviceaccount.com"
}
```

## Remediated example
```hcl
resource "google_project_iam_member" "pipeline_scoped" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:pipeline-runner@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Identify the actual set of resources/actions the service account's workload needs to perform.
2. Replace the broad `roles/editor`, `roles/owner`, or any `*Admin` role with the narrowest predefined role (or a custom role) that covers just those actions (e.g., `roles/storage.objectAdmin` instead of `roles/editor` for a workload that only needs to manage GCS objects).
3. If multiple narrow roles are needed, grant each as a separate binding rather than reaching for a broad admin role for convenience.
4. Re-test the workload thoroughly after narrowing permissions — a role that's too narrow will surface as permission-denied errors at runtime, so validate against the actual API calls the workload makes.
5. This is a pure IAM change with no infrastructure downtime, but incorrect narrowing can break production workloads — stage the change and monitor for `PERMISSION_DENIED` errors in Cloud Audit Logs / Cloud Logging after rollout.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleProjectAdminServiceAccount.py)
- [GCP: Best practices for using service accounts](https://cloud.google.com/iam/docs/best-practices-service-accounts)
