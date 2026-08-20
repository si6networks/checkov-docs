# CKV_AWS_222: Ensure DMS replication instance gets all minor upgrade automatically
## Severity
**LOW** (score: 2.0/10)

Without automatic minor version upgrades, a DMS replication instance can miss timely security patches, gradually widening its exposure to known vulnerabilities.

## Summary
This check ensures that an AWS DMS replication instance (`aws_dms_replication_instance`) has `auto_minor_version_upgrade` enabled so it automatically receives minor engine version upgrades, including security patches.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_dms_replication_instance`

## Why it matters
DMS replication instances run a managed replication engine that, like any software, receives periodic minor version updates containing bug fixes and — importantly — security patches for the underlying engine. If automatic minor version upgrades are disabled, the instance can remain on an older, unpatched engine version indefinitely, since no one is prompted to manually apply the update until a major version deprecation forces the issue. A replication instance that stays unpatched against known engine vulnerabilities remains exposed to any publicly disclosed CVEs affecting that version for longer than necessary, which is particularly concerning because DMS instances have privileged connectivity to (and often hold credentials for) both source and target production databases — a compromised replication engine could serve as a pivot point into your core data stores.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `auto_minor_version_upgrade` attribute:
- If `auto_minor_version_upgrade` is set to `true`, the check **PASSES**.
- If it is `false` or absent, the check **FAILS** (default missing-block behavior for `BaseResourceValueCheck`, and the expected value defaults to `True` since no `get_expected_value()` override is given).

## Non-compliant example
```hcl
resource "aws_dms_replication_instance" "example" {
  replication_instance_id     = "example-dms-instance"
  replication_instance_class  = "dms.t3.medium"
  allocated_storage           = 50
  publicly_accessible         = false
  auto_minor_version_upgrade  = false
}
```

## Remediated example
```hcl
resource "aws_dms_replication_instance" "example" {
  replication_instance_id     = "example-dms-instance"
  replication_instance_class  = "dms.t3.medium"
  allocated_storage           = 50
  publicly_accessible         = false
  auto_minor_version_upgrade  = true
}
```

## Remediation steps
1. Set `auto_minor_version_upgrade = true` on the `aws_dms_replication_instance` resource.
2. Confirm your DMS maintenance window (`preferred_maintenance_window`) is set to a time that minimizes disruption, since automatic minor upgrades apply during that window and can briefly interrupt or fail over replication tasks.
3. If you have strict change-control requirements that prevent automatic upgrades, consider instead implementing a documented manual patching cadence and tracking it outside of this automatic mechanism, along with a Checkov suppression comment explaining the compensating control.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DMSReplicationInstanceMinorUpgrade.py)
- [AWS DMS: Working with a Replication Instance](https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html)
