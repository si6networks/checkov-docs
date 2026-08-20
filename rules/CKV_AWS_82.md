# CKV_AWS_82: Ensure Athena Workgroup should enforce configuration to prevent client disabling encryption
## Severity
**MEDIUM** (score: 5.0/10)

An Athena workgroup that does not enforce its encryption configuration allows individual queries to override and disable encryption, undermining protection of query results that may contain sensitive data.

## Summary
This check fails when an Athena Workgroup does not have `EnforceWorkGroupConfiguration` set to true, which would otherwise allow individual query clients to override the workgroup's centrally defined settings (including encryption requirements) on a per-query basis.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Athena::WorkGroup` (CloudFormation), `aws_athena_workgroup` (Terraform)
- **Check type:** resource

## Why it matters
Athena Workgroups can centrally define query result encryption, output location, and other settings — but only if `EnforceWorkGroupConfiguration` is enabled. If it is left disabled (or absent, depending on framework defaults), any client submitting a query can override the workgroup's settings at query time, including specifying a different (potentially unencrypted or attacker-controlled) output S3 location, or disabling result encryption entirely. This defeats the purpose of centrally managing security controls for a shared analytical environment: an administrator may believe encryption is enforced org-wide via the workgroup configuration, while in reality any analyst or automated job with query permissions can silently write unencrypted (or misrouted) query results, undermining both data-at-rest protections and any DLP/output-location controls the workgroup was meant to guarantee.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/WorkGroupConfiguration/EnforceWorkGroupConfiguration`, with the default expected value of `True` (the base class default). Fails if this is not explicitly `true`.
- **Terraform:** inspects `configuration/[0]/enforce_workgroup_configuration`, also expecting `true`. Notably, this implementation sets `missing_block_result=CheckResult.PASSED` — meaning if the `configuration` block is entirely absent, the check **passes**, because AWS's own default for `enforce_workgroup_configuration` is `true` when omitted. It only fails if the attribute is explicitly present and set to `false`.

## Non-compliant example
```hcl
resource "aws_athena_workgroup" "analysts" {
  name = "analysts-workgroup"

  configuration {
    enforce_workgroup_configuration = false

    result_configuration {
      output_location = "s3://analysts-query-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
```

## Remediated example
```hcl
resource "aws_athena_workgroup" "analysts" {
  name = "analysts-workgroup"

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      output_location = "s3://analysts-query-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
```

## Remediation steps
1. Set `enforce_workgroup_configuration = true` (Terraform) or `EnforceWorkGroupConfiguration: true` (CloudFormation) explicitly within the workgroup's configuration block — do not rely on omission, since Checkov (and good practice) treats explicit enforcement as the safer, auditable state.
2. Ensure the workgroup's `result_configuration.encryption_configuration` is itself set (see CKV_AWS_77 for the related database-level encryption check) so that once enforced, clients are actually forced into an encrypted, centrally-controlled output path.
3. Communicate to query authors that per-query overrides of output location/encryption will now be rejected, since queries that previously specified a different (permissive) configuration will start failing.
4. This is a non-disruptive Athena-side setting change; no resource replacement required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AthenaWorkgroupConfiguration.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/AthenaWorkgroupConfiguration.py)
- [Amazon Athena workgroups](https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html)
