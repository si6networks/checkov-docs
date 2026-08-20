# CKV_ALI_5: Ensure Action Trail Logging for all events
## Severity
**MEDIUM** (score: 5.0/10)

Logging only reads or only writes instead of all events leaves a class of account activity (e.g. write operations) unrecorded, undermining the audit trail needed to detect and investigate compromise.

## Summary
This check ensures that an Alibaba Cloud ActionTrail trail is configured to log both read and write API events (`event_rw = "All"`), not just one category.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_actiontrail_trail`

## Why it matters
ActionTrail can be scoped to log only read events, only write events, or all events. If a trail only captures write events, reconnaissance activity performed via read-only API calls (e.g., an attacker enumerating IAM policies, security group rules, or storage bucket configurations to plan a subsequent attack) leaves no audit trail at all. Conversely, if only reads are logged, actual destructive or configuration-changing actions go unrecorded. Both scenarios create a significant blind spot: mature attack campaigns typically begin with extensive read-only reconnaissance before executing a write action, and a partial trail severs the ability to reconstruct the full attack chain during incident response.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `event_rw` attribute of `alicloud_actiontrail_trail`.
- **Missing block/attribute:** treated as **FAILED** (`missing_block_result=CheckResult.FAILED`) — unlike the region check, an unset `event_rw` is explicitly non-compliant here.
- **FAIL** if `event_rw` is missing, or set to a value other than `"All"` (e.g., `"Write"` or `"Read"` only).
- **PASS** if `event_rw = "All"`.

## Non-compliant example
```hcl
resource "alicloud_actiontrail_trail" "example" {
  trail_name       = "example-trail"
  oss_bucket_name  = alicloud_oss_bucket.example.bucket
  trail_region     = "All"
  event_rw         = "Write"  # only write events are logged
}
```

## Remediated example
```hcl
resource "alicloud_actiontrail_trail" "example" {
  trail_name       = "example-trail"
  oss_bucket_name  = alicloud_oss_bucket.example.bucket
  trail_region     = "All"
  event_rw         = "All"    # <-- changed: captures both read and write events
}
```

## Remediation steps
1. Explicitly set `event_rw = "All"` on every `alicloud_actiontrail_trail` resource.
2. If cost or log-volume is a concern with logging all read events, evaluate lifecycle/archival policies on the destination OSS bucket rather than narrowing the event scope.
3. Re-apply; this is a non-disruptive configuration change to the existing trail.
4. Pair with `trail_region = "All"` (CKV_ALI_4) for complete multi-region, all-event audit coverage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/ActionTrailLogAllEvents.py)
