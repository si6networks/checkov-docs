# CKV_AWS_390: Ensure AWS EMR block public access setting is enabled
## Severity
**HIGH** (score: 7.5/10)

Disabling EMR's block-public-access setting can leave cluster security groups reachable from the internet, exposing a data-processing cluster and the datasets it operates on to unauthenticated network access.

## Summary
This check ensures that the account-level EMR block-public-access configuration has `block_public_security_group_rules` set to `true`, preventing EMR clusters from being launched with security group rules that allow unrestricted inbound access.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_emr_block_public_access_configuration`

## Why it matters
AWS EMR's block-public-access configuration is an account/region-level guardrail that prevents EMR clusters from being provisioned with security groups that permit public (0.0.0.0/0) inbound traffic on ports other than an explicitly allowed exception list (e.g., port 22). Without this setting enabled, an engineer who misconfigures a cluster's security group — even accidentally — could expose the EMR master or core node's management ports (Hadoop web UIs, YARN ResourceManager, Livy, Zeppelin, etc.) directly to the internet. These services frequently have no independent authentication layer and have been a repeated source of cluster takeover and cryptomining incidents when left open. Enabling this configuration acts as a defense-in-depth safety net independent of any single cluster's own security group hygiene.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` against `aws_emr_block_public_access_configuration` resources. It inspects the `block_public_security_group_rules` attribute:
- **PASS** if `block_public_security_group_rules = true` (the default expected value for `BaseResourceValueCheck` is `true`/truthy).
- **FAIL** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "aws_emr_block_public_access_configuration" "example" {
  block_public_security_group_rules = false
}
```

## Remediated example
```hcl
resource "aws_emr_block_public_access_configuration" "example" {
  block_public_security_group_rules = true

  permitted_public_security_group_rule_range {
    min_range = 22
    max_range = 22
  }
}
```

## Remediation steps
1. Add or update the `aws_emr_block_public_access_configuration` resource in your account/region so that `block_public_security_group_rules` is set to `true`.
2. If specific ports must remain open to the public internet (rare — e.g., a bastion-less SSH scenario), use `permitted_public_security_group_rule_range` blocks to scope narrow, justified exceptions rather than disabling the whole guardrail.
3. Note this is an account/region-singleton setting in AWS — only one such configuration exists per account per region, so ensure your Terraform state doesn't attempt to manage duplicate resources across modules.
4. Re-run `checkov` to confirm the resource now passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRPubliclyAccessible.py)
- [AWS EMR block public access documentation](https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html)
