# CKV_AWS_141: Ensured that Redshift cluster allowing version upgrade by default

## Severity
**LOW** (score: 2.0/10)

Allowing automatic version upgrades on Redshift is an operational/change-management consideration (unplanned upgrade timing) with only indirect and minor security relevance.

## Summary
This check requires `aws_redshift_cluster` resources to have `allow_version_upgrade` enabled (or left unset, which defaults to enabled), so the cluster automatically receives maintenance-track version upgrades rather than being pinned indefinitely to its current engine version.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_redshift_cluster`

## Why it matters
Blocking automatic version upgrades means the cluster will not receive newer Redshift engine versions during its maintenance window, which include security patches, bug fixes, and performance improvements released by AWS. Falling behind on engine versions leaves known, already-patched vulnerabilities unaddressed for longer, increasing the window in which the cluster could be exploited via a flaw that AWS has already fixed upstream. It also risks larger, more disruptive jumps later (skipping several versions at once) when an upgrade eventually becomes unavoidable (e.g., end-of-support for the current version), rather than incrementally absorbing smaller, well-tested version bumps.

## How Checkov evaluates this
The check (`RedshiftClusterAllowVersionUpgrade`, `BaseResourceValueCheck`, default expected value `True`):
- Inspects the `allow_version_upgrade` attribute.
- **PASS** if `allow_version_upgrade = true`.
- **FAIL** if explicitly set to `false`.
- If the attribute is **missing entirely**, the check is configured with `missing_block_result=CheckResult.PASSED` — this aligns with the AWS default for Redshift, which is `true` (upgrades allowed) when unset.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier      = "app-warehouse"
  node_type               = "dc2.large"
  master_username         = "admin"
  master_password         = var.redshift_password
  allow_version_upgrade   = false   # FAIL: blocks automatic engine upgrades
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier      = "app-warehouse"
  node_type               = "dc2.large"
  master_username         = "admin"
  master_password         = var.redshift_password
  allow_version_upgrade   = true   # changed / restored default
}
```

## Remediation steps
1. Remove any explicit `allow_version_upgrade = false` from the `aws_redshift_cluster` resource, or set it explicitly to `true`.
2. Configure a `preferred_maintenance_window` so upgrades occur during a predictable, low-traffic period rather than an arbitrary time.
3. If there is a genuine operational reason to pin the engine version temporarily (e.g., validating compatibility before a major version bump), track this as a time-boxed exception rather than a permanent setting, and re-enable upgrades once validated.
4. This is a non-disruptive configuration attribute; actual upgrades still only occur during the cluster's maintenance window, not immediately on `apply`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterAllowVersionUpgrade.py)
- [AWS: Managing clusters using the console (maintenance windows and version upgrades)](https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html)
