# CKV_YC_24: Ensure passport account is not used for assignment. Use service accounts and federated accounts where possible.

## Severity
**MEDIUM** (score: 5.5/10)

Binding IAM roles directly to a personal passport (user) account instead of a service or federated account weakens centralized access governance and offboarding controls, increasing the risk of lingering or unaccountable access rather than creating an immediate exploitable exposure.

## Summary
This check ensures that Yandex Cloud IAM role bindings/members at the folder, cloud, or organization level are not granted directly to "passport account" (individual user account, `userAccount:...`) identities — favoring service accounts or federated identities instead.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_resourcemanager_folder_iam_binding`, `yandex_resourcemanager_folder_iam_member`, `yandex_resourcemanager_cloud_iam_binding`, `yandex_resourcemanager_cloud_iam_member`, `yandex_organizationmanager_organization_iam_binding`, `yandex_organizationmanager_organization_iam_member`
- **Check type:** resource

## Why it matters
A "passport account" (`userAccount`) in Yandex Cloud represents an individual person's Yandex login. Granting IAM roles directly to individual user accounts, especially at cloud- or organization-wide scope, creates several risks:
- **Weak lifecycle management**: when an employee leaves or changes teams, access tied to their personal account must be manually revoked everywhere it was granted, which is easily missed and leads to orphaned/stale access.
- **No centralized identity governance**: individual user grants bypass centralized identity providers (SSO/federation), making it harder to enforce MFA policies, conditional access, and audit trails consistently across an organization.
- **Reduced auditability and non-repudiation**: personal accounts can be shared informally or have weaker credential hygiene than managed service accounts, and it's harder to correlate access reviews across many individually-granted permissions than through group/federated role assignment.
- **Poor separation of human vs. machine identity**: workloads and automation should authenticate via service accounts (with keys/managed identities), not by binding infrastructure permissions to a human's personal login, which conflates human and machine trust boundaries.
Best practice is to grant roles to service accounts (for workloads/automation) or to federated identities managed through an external IdP (for humans), where group membership and lifecycle are centrally governed.

## How Checkov evaluates this
This is a Python `scan_resource_conf` check (not a generic negative-value check) that branches on `self.entity_type`:
- For `*_iam_binding` resources (`folder`, `cloud`, `organization`), it iterates the `members` list; if **any** entry starts with the string `"userAccount"`, the check **FAILS**.
- For `*_iam_member` resources, it checks whether the single `member` value starts with `"userAccount"`; if so, the check **FAILS**.
- Any member string that starts with something else (e.g., `serviceAccount:...`, `federatedUser:...`, `group:...`) causes that entity to **PASS**.
The evaluated keys reported are `members` and `member`.

## Non-compliant example
```hcl
resource "yandex_resourcemanager_cloud_iam_member" "bad_example" {
  cloud_id = "b1gxxxxxxxxxxxxxxxxx"
  role     = "viewer"
  # Direct grant to an individual Yandex passport account
  member   = "userAccount:aje00xxxxxxxxxxxxxxx"
}
```

## Remediated example
```hcl
resource "yandex_iam_service_account" "automation" {
  name       = "ci-automation-sa"
  folder_id  = "b1gxxxxxxxxxxxxxxxxx"
}

resource "yandex_resourcemanager_cloud_iam_member" "good_example" {
  cloud_id = "b1gxxxxxxxxxxxxxxxxx"
  role     = "viewer"
  # Grant to a service account instead of a personal user account
  member   = "serviceAccount:${yandex_iam_service_account.automation.id}"
}
```

## Remediation steps
1. Determine whether the access is for a human or a workload. For workloads/automation, create/use a `yandex_iam_service_account` and grant roles to `serviceAccount:<id>` instead of `userAccount:<id>`.
2. For human access, integrate a federated identity provider (SAML/OIDC via Yandex Cloud Organization) so users authenticate through your central IdP, and grant roles to `federatedUser:...` or to a `group:...` managed there.
3. Migrate existing direct `userAccount` grants to the appropriate service account or federated/group identity, then remove the old member entry.
4. Establish a periodic access review to catch any new direct `userAccount` grants creeping back in.
5. Re-scan with Checkov to confirm no `members`/`member` values start with `userAccount`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/IAMPassportAccountUsage.py
