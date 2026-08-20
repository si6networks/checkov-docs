# CKV_YC_21: Ensure organization member does not have elevated access

## Severity
**CRITICAL** (score: 9.2/10)

Granting admin/owner-level roles at the organization level is a wildcard-style privilege grant that can affect every cloud and resource under the organization, making compromise of that principal catastrophic in scope.

## Summary
This check fails when a Yandex Cloud Organization Manager IAM binding/member resource grants a broad organization-level administrative role (`admin`, `editor`, or organization owner/admin roles) to a member.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `yandex_organizationmanager_organization_iam_binding`, `yandex_organizationmanager_organization_iam_member`

## Why it matters
Organization-level IAM in Yandex Cloud sits above individual clouds and folders — it's the root of the resource hierarchy. Granting broad roles such as `admin`, `editor`, `organization-manager.organizations.owner`, or `organization-manager.admin` at this scope gives a member sweeping control over every cloud, folder, and resource within the entire organization, plus the ability to manage organization-wide IAM policy, billing, and membership itself. This is an even higher-impact grant than cloud-level elevated access (CKV_YC_13): compromise of a credential holding one of these roles can result in complete organizational takeover — creating new clouds, exfiltrating data across all business units, deleting resources organization-wide, or granting persistent backdoor access even after other remediation efforts. Least-privilege principles dictate that these primitive, catch-all roles should be reserved for a very small number of tightly controlled break-glass accounts, not routinely assigned via standing Terraform-managed bindings.

## How Checkov evaluates this
The check (`IAMOrganizationElevatedMembers`) is a `BaseResourceNegativeValueCheck` that inspects the `role` attribute:
- The forbidden values are `["admin", "editor", "organization-manager.organizations.owner", "organization-manager.admin"]`.
- If `role` matches any of these values, the check **FAILS**.
- Any other, narrower role **PASSES**.

## Non-compliant example
```hcl
resource "yandex_organizationmanager_organization_iam_member" "external_admin" {
  organization_id = yandex_organizationmanager_organization.default.id
  role            = "organization-manager.admin"  # org-wide elevated role -- FAILS CKV_YC_21
  member          = "userAccount:aje6r81ellf2vora7935"
}
```

## Remediated example
```hcl
resource "yandex_organizationmanager_organization_iam_member" "external_viewer" {
  organization_id = yandex_organizationmanager_organization.default.id
  role            = "organization-manager.organizations.viewer"  # scoped, read-only role -- PASSES CKV_YC_21
  member          = "userAccount:aje6r81ellf2vora7935"
}
```

## Remediation steps
1. Determine the minimum permissions the member genuinely requires (e.g., viewing organization structure, managing a specific cloud, managing billing only).
2. Replace `admin`/`editor`/organization owner/admin role grants with a narrower predefined or custom role scoped to the specific resource hierarchy level (cloud, folder) and the specific actions needed.
3. Reserve organization-level `admin`/owner roles for a minimal set of tightly controlled, monitored break-glass accounts — manage these outside routine Terraform IAM bindings where possible, with additional approval workflows.
4. Enforce multi-factor authentication and conditional access policies for any account that does hold organization-level elevated roles.
5. Periodically audit all organization-level IAM bindings for scope creep and remove unused elevated grants.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/IAMOrganizationElevatedMembers.py)
- [Yandex Cloud Organization Manager documentation](https://yandex.cloud/en/docs/organization/)
