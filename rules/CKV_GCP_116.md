# CKV_GCP_116: Ensure basic roles are not used at folder level.

## Severity
**MEDIUM** (score: 5.0/10)

Basic roles at the folder level grant broad Owner/Editor/Viewer permissions across all projects under that folder, which is overly permissive access that violates least privilege for a large resource hierarchy.

## Summary
This check fails when a `google_folder_iam_member` or `google_folder_iam_binding` resource assigns a legacy GCP basic role (`roles/owner`, `roles/editor`, `roles/viewer`) at the folder level, since folder-level grants cascade to every project and sub-folder beneath them.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_folder_iam_member`, `google_folder_iam_binding`
- **Check type:** resource

## Why it matters
GCP folders are used to group projects (often mapping to business units, environments, or teams). An IAM grant at the folder level is inherited by every project and nested folder within it. Basic roles are dangerously broad:
- `roles/owner` allows full administrative control, including changing IAM policy, over every project in the folder subtree.
- `roles/editor` allows modifying nearly all resources across every project in the folder subtree.
- `roles/viewer` allows reading nearly all resource configuration and metadata across the subtree, which can still leak secrets references, network topology, and other sensitive design information.

Because folders often correspond to environment boundaries (e.g. "production" folder containing dozens of projects), a single basic-role grant at the folder level can give a principal blanket access across an entire business unit or environment — turning what should be a scoped, reviewable grant into a wide blast radius if the identity is ever compromised or misused.

## How Checkov evaluates this
The check (`GoogleFolderBasicRoles`, via the shared `AbsGoogleBasicRoles` base class) inspects the resource's `role` attribute:
- It reads the first element of the `role` list.
- If the role is one of `roles/owner`, `roles/editor`, or `roles/viewer`, the check returns **FAILED**.
- Any other (predefined narrow or custom) role returns **PASSED**.
- The evaluated key is `role`.

## Non-compliant example
```hcl
resource "google_folder_iam_binding" "prod_folder_owner" {
  folder = "folders/987654321098"
  role   = "roles/owner"

  members = [
    "group:platform-team@example.com",
  ]
}
```

## Remediated example
```hcl
resource "google_folder_iam_binding" "prod_folder_scoped" {
  folder = "folders/987654321098"
  role   = "roles/compute.admin"  # scoped predefined role instead of basic "owner"

  members = [
    "group:platform-team@example.com",
  ]
}
```

## Remediation steps
1. Determine the minimum set of permissions the group/user actually needs across the folder's projects.
2. Replace the basic role with one or more predefined roles (e.g. `roles/compute.admin`, `roles/iam.securityReviewer`) or a custom role scoped to those permissions.
3. If different projects in the folder need different access levels, consider granting roles at the individual project level instead of the folder, to reduce blast radius.
4. Apply the change and validate with `gcloud projects get-ancestors-iam-policy` / `gcloud resource-manager folders get-iam-policy <FOLDER_ID>` that inherited access matches expectations.
5. Periodically review folder-level bindings, since they are easy to forget and their inherited effect is not always visible when looking at an individual project's IAM page.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleFolderBasicRole.py)
- [GCP resource hierarchy and IAM inheritance](https://cloud.google.com/iam/docs/resource-hierarchy-access-control)
