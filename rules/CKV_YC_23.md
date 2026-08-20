# CKV_YC_23: Ensure folder member does not have elevated access.

## Severity
**HIGH** (score: 7.5/10)

Granting a folder member the built-in "admin" or "editor" role hands out broad, near-owner-level privileges across every resource in the folder, dramatically expanding the blast radius of a single compromised or over-provisioned identity.

## Summary
This check flags Yandex Cloud Resource Manager folder-level IAM bindings/members that grant the built-in `admin` or `editor` roles, which are broad, elevated privileges that should not be assigned directly to folder members.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `yandex_resourcemanager_folder_iam_binding`, `yandex_resourcemanager_folder_iam_member`
- **Check type:** resource (negative value check)

## Why it matters
Yandex Cloud's `admin` and `editor` predefined roles are extremely broad — `admin` grants nearly full control over the folder including IAM policy management, and `editor` grants read/write access to nearly all resources within the folder (with a few exceptions like IAM policy itself). Assigning either role directly to an individual member (a user, service account, or group) at the folder scope violates least-privilege principles: it means a single compromised credential, a phished user, or a misconfigured service account can read, modify, or delete essentially anything in that folder — VMs, storage buckets, databases, network configuration — and in the case of `admin`, can also re-assign IAM permissions to escalate further or create backdoor access for other identities. Broad folder-level grants also make it much harder to reason about blast radius during an incident, since a single principal has authority over many unrelated workloads. The security best practice is to grant narrowly-scoped, resource-specific, or custom roles instead of blanket `admin`/`editor` at the folder level.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`. Checkov inspects the `role` attribute of the resource:
- For `yandex_resourcemanager_folder_iam_member`, it reads the single `role` value.
- For `yandex_resourcemanager_folder_iam_binding`, it reads the `role` value that applies to the binding (which can list multiple `members`).

If the `role` value equals `"admin"` or `"editor"` (the forbidden values), the check **FAILS**. Any other role value (e.g., a narrower predefined role such as `viewer`, or a custom/least-privilege role) **PASSES**.

## Non-compliant example
```hcl
resource "yandex_resourcemanager_folder_iam_member" "bad_example" {
  folder_id = "b1gxxxxxxxxxxxxxxxxx"
  role      = "editor"
  member    = "userAccount:aje00xxxxxxxxxxxxxxx"
}
```

## Remediated example
```hcl
resource "yandex_resourcemanager_folder_iam_member" "good_example" {
  folder_id = "b1gxxxxxxxxxxxxxxxxx"
  # Use a narrowly scoped role instead of "editor" or "admin"
  role      = "storage.viewer"
  member    = "userAccount:aje00xxxxxxxxxxxxxxx"
}
```

## Remediation steps
1. Identify what the member actually needs to do, and grant the most specific predefined role that covers that need (e.g., `storage.editor`, `compute.admin` for a specific service, `viewer` for read-only access) instead of folder-wide `admin`/`editor`.
2. If no predefined role fits, define a custom IAM role in Yandex Cloud scoped to only the required permissions.
3. Prefer assigning elevated roles to groups or service accounts with tightly controlled membership rather than directly to individual user accounts, and audit membership regularly.
4. If `admin`/`editor` access is genuinely required (e.g., for a small trusted admin team), consider granting it at a more granular resource level rather than the whole folder, or use time-bound/temporary elevated access processes if your organization supports them.
5. Re-run Checkov after remediation to confirm the `role` value no longer matches `admin` or `editor`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/IAMFolderElevatedMembers.py
