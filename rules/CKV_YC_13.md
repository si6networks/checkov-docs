# CKV_YC_13: Ensure cloud member does not have elevated access

## Severity
**CRITICAL** (score: 9.2/10)

Granting a cloud member the admin or editor role is equivalent to wildcard IAM administrative access over the entire cloud, allowing full control of resources, data, and further privilege escalation if the principal is compromised.

## Summary
This check fails when a Yandex Cloud IAM binding/member resource grants the broad `admin` or `editor` role at the cloud level.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_resourcemanager_cloud_iam_binding`, `yandex_resourcemanager_cloud_iam_member`

## Why it matters
The `admin` and `editor` roles at the cloud level are extremely broad, primitive IAM roles granting near-total control over every resource within the cloud (create/modify/delete compute, storage, databases, networking, and — critically — IAM policy itself in the case of `admin`). Assigning these roles to individual members (rather than using scoped, resource-specific, or custom roles following least privilege) means that a single compromised credential (phished user, leaked service-account key, or insider misuse) can result in complete compromise of the entire cloud environment — including data exfiltration, resource destruction, and privilege-escalation persistence (e.g., an attacker with `admin` can grant themselves further access even after being partially locked out). This check enforces a least-privilege IAM posture by flagging use of these primitive elevated roles at the cloud scope, encouraging narrower role grants instead.

## How Checkov evaluates this
The check (`IAMCloudElevatedMembers`) is a `BaseResourceNegativeValueCheck` that inspects the `role` attribute:
- The forbidden values are `["admin", "editor"]`.
- If `role` is set to `"admin"` or `"editor"`, the check **FAILS**.
- Any other role value (e.g., a scoped/custom role) **PASSES**.

## Non-compliant example
```hcl
resource "yandex_resourcemanager_cloud_iam_member" "contractor" {
  cloud_id = yandex_resourcemanager_cloud.default.id
  role     = "editor"  # broad elevated role -- FAILS CKV_YC_13
  member   = "userAccount:aje6r81ellf2vora7935"
}
```

## Remediated example
```hcl
resource "yandex_resourcemanager_cloud_iam_member" "contractor" {
  cloud_id = yandex_resourcemanager_cloud.default.id
  role     = "storage.viewer"  # scoped, least-privilege role -- PASSES CKV_YC_13
  member   = "userAccount:aje6r81ellf2vora7935"
}
```

## Remediation steps
1. Identify the minimum set of permissions the member actually needs to perform their job function.
2. Replace `admin`/`editor` role grants with narrower predefined roles (e.g., `storage.editor`, `compute.admin` on a specific folder, `mdb.admin`) or a custom IAM role scoped to specific resources/permissions.
3. Prefer granting roles at the folder level rather than the cloud level wherever possible, further limiting blast radius.
4. If `admin`/`editor` access is genuinely required (e.g., for a break-glass account), manage it outside of standing Terraform-managed IAM bindings — e.g., via just-in-time access processes with additional approval and logging — rather than a persistent Terraform-managed grant.
5. Regularly audit cloud-level IAM bindings for unused or overly broad grants.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/IAMCloudElevatedMembers.py)
- [Yandex Cloud IAM roles documentation](https://yandex.cloud/en/docs/iam/concepts/access-control/roles)
