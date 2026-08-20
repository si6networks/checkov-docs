# CKV_ALI_4: Ensure Action Trail Logging for all regions
## Severity
**MEDIUM** (score: 5.0/10)

Restricting ActionTrail logging to only some regions creates blind spots where account-level API activity, including malicious actions, goes completely unrecorded.

## Summary
This check ensures that an Alibaba Cloud ActionTrail trail is configured to capture events from all regions (`trail_region = "All"`), not just a single region.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_actiontrail_trail`

## Why it matters
ActionTrail is Alibaba Cloud's equivalent of an API/management-plane audit log (comparable to AWS CloudTrail). If a trail is scoped to only a single region, API calls and resource changes made in any other region — including regions an attacker might specifically target because they know logging is not enabled there — go completely unrecorded. This creates an exploitable blind spot: an attacker with compromised credentials can simply operate in a region outside the trail's scope to avoid detection, and legitimate incident responders will have no audit record to reconstruct what happened. Multi-region logging coverage is a standard cloud security baseline precisely because attackers are known to exploit regional logging gaps.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `trail_region` attribute of `alicloud_actiontrail_trail`.
- **Missing block/attribute:** treated as **PASSED** (`missing_block_result=CheckResult.PASSED`) — i.e., if `trail_region` is not set at all, Checkov assumes the provider default is acceptable.
- **FAIL** if `trail_region` is explicitly set to a value other than `"All"` (e.g., a specific region like `"cn-hangzhou"`).
- **PASS** if `trail_region` is explicitly set to `"All"`, or left unset.

## Non-compliant example
```hcl
resource "alicloud_actiontrail_trail" "example" {
  trail_name       = "example-trail"
  oss_bucket_name  = alicloud_oss_bucket.example.bucket
  trail_region     = "cn-hangzhou"  # scoped to a single region
  event_rw         = "All"
}
```

## Remediated example
```hcl
resource "alicloud_actiontrail_trail" "example" {
  trail_name       = "example-trail"
  oss_bucket_name  = alicloud_oss_bucket.example.bucket
  trail_region     = "All"  # <-- changed: captures events from all regions
  event_rw         = "All"
}
```

## Remediation steps
1. Set `trail_region = "All"` explicitly on every `alicloud_actiontrail_trail` resource.
2. If a single-region trail was intentional for cost or data-residency reasons, document the exception and ensure compensating multi-region monitoring exists elsewhere.
3. Re-apply; this is generally a non-disruptive configuration update to the existing trail.
4. Pair with `event_rw = "All"` (CKV_ALI_5) to also capture both read and write API events, not just one category.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/ActionTrailLogAllRegions.py)
