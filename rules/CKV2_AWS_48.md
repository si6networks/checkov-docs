# CKV2_AWS_48: Ensure AWS Config must record all possible resources
## Severity
**LOW** (score: 2.0/10)

When AWS Config does not record global resource types (e.g., IAM), account-wide identity and access changes go unaudited, weakening detection of privilege-related misconfigurations.

## Summary
This check fails when an AWS Config configuration recorder's `recording_group.include_global_resource_types` attribute is not set to `true`, meaning the recorder does not track changes to global (non-region-scoped) resources such as IAM.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_config_configuration_recorder`

## Why it matters
Some AWS resource types are global rather than regional — most importantly IAM users, groups, roles, and policies, but also things like CloudFront distributions and Route 53 hosted zones. If `include_global_resource_types` is left `false` (or unset in a way that resolves to false), AWS Config will faithfully record every regional resource but stay silent on IAM changes entirely. Since IAM is the identity and access control plane, this is exactly the blind spot an attacker (or a careless admin) benefits from: a new IAM user created, a policy attached granting broad permissions, or a role's trust policy modified to allow cross-account assumption would leave no trace in Config's configuration history or trigger no Config Rules evaluation. Compliance frameworks (CIS AWS Foundations, PCI-DSS, SOC 2) commonly require IAM change tracking specifically, so missing this also creates an audit gap.

## How Checkov evaluates this
This is a graph-based JSON policy checking a single attribute:
- **Attribute checked:** `recording_group.include_global_resource_types` on `aws_config_configuration_recorder`
- **Operator:** `equals`, value `"true"`
- **PASS** only if the attribute is explicitly set to `true`.
- **FAIL** if the attribute is `false`, or absent (Terraform/AWS default behavior can vary and Checkov does not treat an unset value as compliant here — it must be explicit).
- Note: only one region's recorder needs `include_global_resource_types = true` in a multi-region Config setup (AWS itself recommends enabling it in exactly one region to avoid duplicate global-resource events), but Checkov evaluates each recorder resource independently against this rule.

## Non-compliant example
```hcl
resource "aws_config_configuration_recorder" "bad" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = false
  }
}
```

## Remediated example
```hcl
resource "aws_config_configuration_recorder" "good" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}
```

## Remediation steps
1. Set `recording_group.include_global_resource_types = true` on the `aws_config_configuration_recorder`.
2. In a multi-region deployment, enable this on only one recorder (typically your primary/home region) to avoid redundant global-resource change events across regions — check other regions' recorders don't also have it enabled unintentionally.
3. Pair this with `all_supported = true` (see CKV2_AWS_45) so both regional and global resource types are fully covered.
4. Confirm the Config service role has permissions to describe IAM and other global resources (`AWS_ConfigRole` managed policy covers this by default).
5. No downtime/replacement is required — this is an in-place attribute update on an existing recorder.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ConfigRecorderRecordsAllGlobalResources.json
- AWS docs: https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html
