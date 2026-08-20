# CKV_AWS_238: Ensure that GuardDuty detector is enabled

## Severity
**LOW** (score: 2.0/10)

A disabled GuardDuty detector silently blinds the account to the threat-detection findings (reconnaissance, credential exfiltration, malicious IP communication, etc.) it exists to surface, a genuine loss of security-relevant monitoring.

## Summary
This check ensures that an `aws_guardduty_detector` resource is actively enabled rather than provisioned in a disabled state.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_guardduty_detector`

## Why it matters
Amazon GuardDuty is AWS's managed threat-detection service, continuously analyzing VPC Flow Logs, DNS logs, CloudTrail management/data events, and (optionally) EKS audit logs and S3 data events to detect indicators of compromise — reconnaissance, credential exfiltration, cryptomining, unusual API call patterns, communication with known-malicious IPs, and more. A detector resource that exists in Terraform state but is disabled (`enable = false`) gives a false sense of security: the resource shows up as "configured" in an infrastructure inventory or compliance report, but it is not actually monitoring anything, and no findings will be generated regardless of what malicious activity occurs in the account. This is a particularly dangerous class of misconfiguration because it is easy to overlook — the resource is present, so a shallow audit ("do we have GuardDuty configured?") would answer yes, while the account is in fact blind to the threats GuardDuty is meant to catch.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `enable` attribute of the `aws_guardduty_detector` resource.
- If the `enable` attribute is **absent entirely**, the check treats this as a PASS (`missing_block_result=CheckResult.PASSED`) — Terraform's own default for `enable` is `true`.
- **PASS** if `enable` is explicitly `true`.
- **FAIL** if `enable` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "aws_guardduty_detector" "main" {
  enable = false
}
```

## Remediated example
```hcl
resource "aws_guardduty_detector" "main" {
  enable = true
}
```

## Remediation steps
1. Remove the `enable` attribute entirely (defaults to `true`), or set it explicitly to `true`.
2. Confirm at the account/organization level that GuardDuty is also enabled — if using AWS Organizations, verify a delegated administrator account has GuardDuty enabled for all member accounts, since a per-account Terraform resource only reflects that specific account.
3. Pair this with configuring finding export (e.g. `aws_guardduty_detector.finding_publishing_frequency` and downstream S3/EventBridge integration) so findings are actually consumed and acted upon, not just generated.
4. Re-enabling a detector is a metadata-only change and does not require resource replacement, but note that findings generated while disabled are not retroactively created.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GuarddutyDetectorEnabled.py)
- [Amazon GuardDuty documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
