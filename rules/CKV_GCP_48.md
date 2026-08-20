# CKV_GCP_48: Ensure Default Service account is not used at a folder level

## Severity
**HIGH** (score: 7.5/10)

Binding a project's default (often over-privileged) service account at the folder level lets a single compromised workload inherit elevated IAM access across every project nested under that folder, a broad lateral-movement/privilege-escalation path.

## Summary
This check fails when a `google_folder_iam_member` or `google_folder_iam_binding` resource grants IAM access at a GCP folder scope to a project's default service account (the auto-created Compute Engine or App Engine service account) rather than to a dedicated, purpose-built service account.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource types:** `google_folder_iam_member`, `google_folder_iam_binding`
- **Check type:** resource check

## Why it matters
GCP automatically provisions two default service accounts per project:
- `PROJECT_NUMBER-compute@developer.gserviceaccount.com` (Compute Engine default SA)
- `PROJECT_ID@appspot.gserviceaccount.com` (App Engine default SA)

These accounts are broadly known, often over-privileged by default (historically granted `roles/editor` on the project), and are attached implicitly to any VM, Cloud Function, or App Engine app that doesn't specify a custom service account. Any compromised workload running under the default identity inherits whatever IAM bindings exist for it. Binding that identity at the **folder** level compounds the blast radius: a single compromised VM anywhere in the project could gain the granted role across every project nested under the folder, not just the originating project. This violates least-privilege and makes credential-theft incidents far harder to contain, since the default SA's key/token is exposed to any code running on the instance's metadata server.

## How Checkov evaluates this
The check (`GoogleFolderMemberDefaultServiceAccount`, via the shared base class `AbsGoogleIAMMemberDefaultServiceAccount`) inspects the `member` (for `google_folder_iam_member`) or `members` (for `google_folder_iam_binding`) attribute. It applies this regex to each configured member string:

```python
DEFAULT_SA = re.compile(r".*-compute@developer\.gserviceaccount\.com|.*@appspot\.gserviceaccount\.com")
```

- **FAIL** if any member matches the pattern (i.e., is `serviceAccount:<project-number>-compute@developer.gserviceaccount.com` or `serviceAccount:<project-id>@appspot.gserviceaccount.com`).
- **PASS** otherwise (e.g., a custom service account, a Google group, or a user principal).

## Non-compliant example
```hcl
resource "google_folder_iam_member" "folder_binding" {
  folder = "folders/1234567890"
  role   = "roles/editor"
  member = "serviceAccount:123456789012-compute@developer.gserviceaccount.com"
}
```

## Remediated example
```hcl
resource "google_service_account" "automation" {
  account_id   = "folder-automation-sa"
  display_name = "Folder automation service account"
}

resource "google_folder_iam_member" "folder_binding" {
  folder = "folders/1234567890"
  role   = "roles/editor"
  member = "serviceAccount:${google_service_account.automation.email}"
}
```

## Remediation steps
1. Create a dedicated, minimally-privileged `google_service_account` for whatever workload or automation currently uses the default SA.
2. Replace the `member`/`members` value in the `google_folder_iam_member`/`google_folder_iam_binding` resource with the new service account's email.
3. Grant only the specific roles the workload needs (avoid `roles/editor` or `roles/owner`) — scope them to the narrowest resource level possible (project or resource, rather than folder, if feasible).
4. Update any compute resources (VMs, Cloud Functions, GKE node pools) that were relying on the default SA's folder-level permissions to instead use the new service account.
5. Consider disabling automatic default service account grants for new projects via an Organization Policy (`iam.automaticIamGrantsForDefaultServiceAccounts`).
6. After rollout, revoke the default service account's folder-level binding entirely once no resource depends on it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleFolderMemberDefaultServiceAccount.py)
- [GCP: Best practices for using service accounts](https://cloud.google.com/iam/docs/best-practices-service-accounts)
