# CKV_AWS_121: Ensure AWS Config is enabled in all regions

## Severity
**MEDIUM** (score: 5.0/10)

Without AWS Config aggregating configuration changes across all regions, security teams lose visibility into resource drift and misconfigurations in unmonitored regions, delaying detection of a compromise rather than directly enabling one.

## Summary
Fails when an `aws_config_configuration_aggregator` resource does not aggregate configuration data from all regions (via either account-based or organization-based aggregation with `all_regions` set).

## Applicability
- **Terraform**: `aws_config_configuration_aggregator` resource.

## Why it matters
AWS Config records resource configuration changes and evaluates them against compliance rules, but each AWS Config recorder is region-scoped. Attackers and misconfigurations are not limited to whichever regions security teams actively monitor — a common technique for evading detection is deploying resources into a region the organization does not typically use or actively watch ("shadow regions"). If Config aggregation is scoped to only specific regions rather than all regions:
- Resources created or modified in unmonitored regions have no configuration history and are not evaluated against compliance rules, creating blind spots.
- Incident responders investigating an account-wide compromise may miss resources or changes in regions outside the aggregator's scope.
- Compliance reporting understates true account/organization posture, since regions outside scope are invisible to auditors relying on the aggregator.

Setting `all_regions = true` (on account-based or organization-based aggregation) ensures no region is silently excluded from configuration visibility and compliance evaluation, including regions enabled after the aggregator was first configured.

## How Checkov evaluates this
The check inspects the `aws_config_configuration_aggregator` resource for either an `account_aggregation_source` or an `organization_aggregation_source` block:
- **PASS** if `account_aggregation_source[0].all_regions` is truthy, OR if `organization_aggregation_source[0].all_regions` is truthy.
- **FAIL** otherwise (e.g. neither block present, or present but `all_regions` is false/unset — meaning only an explicit, static list of regions was specified via `regions`).

## Non-compliant example
```hcl
resource "aws_config_configuration_aggregator" "bad" {
  name = "org-aggregator"

  account_aggregation_source {
    account_ids = ["123456789012"]
    regions     = ["us-east-1", "us-west-2"]
    all_regions = false
  }
}
```

## Remediated example
```hcl
resource "aws_config_configuration_aggregator" "good" {
  name = "org-aggregator"

  account_aggregation_source {
    account_ids = ["123456789012"]
    all_regions = true
  }
}
```

## Remediation steps
1. Edit the `account_aggregation_source` (or `organization_aggregation_source`) block and set `all_regions = true`.
2. Remove any explicit `regions` list when using `all_regions = true` — the two are mutually exclusive selection modes; AWS Config will error if both a restrictive region list and `all_regions = true` are set together in a way that conflicts.
3. If aggregating across an AWS Organization, prefer `organization_aggregation_source` with `all_regions = true` and ensure AWS Config's organization-wide trusted access / delegated administrator setup is completed first (via `aws_config_organization_custom_rule`/console setup), since the aggregator alone doesn't enable Config recorders in member accounts.
4. Confirm each account/region actually has an active AWS Config recorder (`aws_config_configuration_recorder` + `aws_config_delivery_channel`) — the aggregator only aggregates data that Config is already recording; it does not itself turn on recording in un-configured regions.
5. Review cost implications: aggregating and recording across all regions increases the volume of configuration items delivered to S3 and evaluated by Config rules, which scales cost roughly with total tracked resource count.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ConfigConfgurationAggregatorAllRegions.py
- AWS documentation: https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html
