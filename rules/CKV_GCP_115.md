# CKV_GCP_115: Ensure basic roles are not used at organization level.

## Severity
**HIGH** (score: 7.5/10)

Basic (primitive) roles like Owner/Editor at the organization level grant broad, undifferentiated permissions across every project in the org, violating least privilege at the widest possible blast radius.

## Summary
This check fails when a `google_organization_iam_member` or `google_organization_iam_binding` resource assigns one of GCP's legacy "basic roles" (`roles/owner`, `roles/editor`, `roles/viewer`) at the organization level, since these roles are extremely broad and apply to every project under the org.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_organization_iam_member`, `google_organization_iam_binding`
- **Check type:** resource

## Why it matters
GCP basic roles predate IAM's fine-grained permission model and grant sweeping access:
- `roles/owner` grants full control over every resource in every project in the org, including the ability to modify IAM policies themselves and to add/remove billing.
- `roles/editor` grants read/write on nearly all resources across every project.
- `roles/viewer` grants read access to nearly everything, which can still expose large amounts of sensitive configuration, secrets metadata, and data across all projects.

Granting any of these at the **organization** level means the assignment cascades to every current and future folder and project in the organization. A single overly-broad binding at this level can turn a minor privilege-escalation bug (e.g., a compromised service account with `roles/editor` at org scope) into a full organizational compromise. Google's own security guidance recommends using granular, custom, or predefined roles scoped to the narrowest level (project or resource) instead of basic roles at the org root.

## How Checkov evaluates this
The check (`GoogleOrgBasicRoles`, via the shared `AbsGoogleBasicRoles` base class) inspects the resource's `role` attribute:
- It reads the first element of the `role` list.
- If that role string is one of `roles/owner`, `roles/editor`, or `roles/viewer`, the check returns **FAILED**.
- Any other role value (predicate/custom role) returns **PASSED**.
- The evaluated key is `role`.

## Non-compliant example
```hcl
resource "google_organization_iam_member" "org_admin" {
  org_id = "123456789012"
  role   = "roles/editor"
  member = "user:contractor@example.com"
}
```

## Remediated example
```hcl
resource "google_organization_iam_member" "org_scoped_role" {
  org_id = "123456789012"
  role   = "roles/resourcemanager.organizationViewer"  # narrowly scoped predefined role
  member = "user:contractor@example.com"
}
```

## Remediation steps
1. Identify the actual permissions the principal needs, then choose a predefined role (e.g. `roles/billing.viewer`, `roles/resourcemanager.folderAdmin`) or a custom role that grants only those permissions.
2. If broad access truly is required, grant it at the narrowest scope possible (a single project) rather than the organization node — avoid basic roles even there.
3. Replace the `role` value and re-apply; note IAM member/binding replacement is non-disruptive to running workloads but changes effective access immediately.
4. Periodically audit existing org-level bindings with `gcloud organizations get-iam-policy <ORG_ID>` to catch bindings created outside Terraform.
5. Consider an [organization policy](https://cloud.google.com/resource-manager/docs/organization-policy/restricting-identities) or IAM recommender to prevent basic-role grants going forward.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleOrgBasicRole.py)
- [GCP basic roles documentation](https://cloud.google.com/iam/docs/understanding-roles#basic)
