# CKV2_AWS_3: Ensure GuardDuty is enabled to specific org/region
## Severity
**LOW** (score: 2.0/10)

GuardDuty not being enabled removes a key threat-detection capability across the account/organization, delaying detection of compromise rather than creating a direct exploitable exposure.

## Summary
This check ensures that an `aws_guardduty_detector` is not only enabled (`enable = true`) but also connected to an `aws_guardduty_organization_configuration` that auto-enables GuardDuty for the AWS Organization's member accounts, so coverage extends organization-wide rather than to a single account/region only.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_guardduty_detector`, `aws_guardduty_organization_configuration`
- **Check type:** Graph-based connection + attribute check

## Why it matters
GuardDuty is AWS's managed threat-detection service, continuously analyzing VPC Flow Logs, DNS logs, and CloudTrail events for indicators of compromise (reconnaissance, credential exfiltration, cryptomining, C2 communication, compromised instances/credentials). If GuardDuty is only enabled in a single account or a subset of accounts within an AWS Organization, any account left out is a blind spot: an attacker who compromises credentials or a workload in an unmonitored member account can operate undetected, and organizational security teams lose the unified, delegated-administrator view that GuardDuty's org-wide configuration is designed to provide. Enabling `auto_enable`/`auto_enable_organization_members` ensures that new accounts joining the organization are automatically covered too, closing the gap that arises when someone forgets to manually enable GuardDuty for a newly created account — a common real-world cause of detection blind spots in multi-account AWS environments.

## How Checkov evaluates this
This is a graph check (`GuardDutyIsEnabled.json`). It requires ALL of:
1. The resource is of type `aws_guardduty_detector`.
2. A graph connection exists from that detector to an `aws_guardduty_organization_configuration` resource.
3. The detector's `enable` attribute equals `true`.
4. Either the organization configuration's `auto_enable` attribute equals `true`, OR its `auto_enable_organization_members` attribute is one of `ALL` or `NEW` (both values that cause new/all member accounts to get GuardDuty automatically).

A detector that is enabled but has no organization configuration attached (i.e., it's a standalone, single-account detector with no `aws_guardduty_organization_configuration`), or an org configuration with `auto_enable = false` and `auto_enable_organization_members = "NONE"`, fails this check.

## Non-compliant example
```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
}
# No aws_guardduty_organization_configuration — GuardDuty only covers this single account
```

## Remediated example
```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_organization_configuration" "org_config" {
  detector_id                     = aws_guardduty_detector.main.id
  auto_enable_organization_members = "ALL"

  datasources {
    s3_logs {
      auto_enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}
```

## Remediation steps
1. Enable GuardDuty in the delegated administrator account (`aws_guardduty_detector` with `enable = true`).
2. Designate that account as the GuardDuty delegated administrator for the AWS Organization (via `aws_guardduty_organization_admin_account` at the organization's management-account level, applied once).
3. In the delegated administrator account, add `aws_guardduty_organization_configuration` referencing the detector, and set `auto_enable_organization_members = "ALL"` (recommended — automatically enrolls all existing and future member accounts) or `"NEW"` (enrolls only new accounts joining after this is set; existing accounts must be onboarded separately).
4. Note: `auto_enable` (the older, non-org-member-scoped attribute) is being deprecated by AWS in favor of `auto_enable_organization_members`; prefer the latter for new configurations, but the check accepts either.
5. Verify member accounts show GuardDuty as "Enabled" via delegated administration, and confirm findings are aggregated to the delegated administrator's GuardDuty console.
6. Caveat: designating a delegated administrator and enabling org-wide auto-enrollment are organization-level AWS API operations — ensure the Terraform run has appropriate `organizations:*` and `guardduty:*` IAM permissions in the management/admin account context.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/GuardDutyIsEnabled.json)
- [AWS GuardDuty multi-account management documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html)
