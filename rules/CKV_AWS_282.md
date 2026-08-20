# CKV_AWS_282: Ensure that Redshift Serverless namespace is encrypted by KMS using a customer managed key (CMK)
## Severity
**HIGH** (score: 7.5/10)

Redshift Serverless namespaces are encrypted by default; not using a customer-managed KMS key limits the organization's ability to control or revoke key access, a key-management gap rather than an unencrypted-data exposure.

## Summary
This check fails when an `aws_redshiftserverless_namespace` resource does not set `kms_key_id`, meaning the Redshift Serverless namespace's data is not confirmed to be encrypted with a customer-managed key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource:** `aws_redshiftserverless_namespace`

## Why it matters
A Redshift Serverless namespace holds the database objects, users, and data for a serverless data warehouse — conceptually the same sensitive analytical data as provisioned Redshift clusters, but managed with a different resource model. If `kms_key_id` is left unset, the namespace falls back to the AWS-owned/AWS-managed default encryption key, which your organization cannot rotate on its own schedule, restrict via a custom key policy, or fully audit key-usage patterns for via CloudTrail with fine-grained control. For workloads subject to compliance regimes requiring customer-controlled encryption keys (PCI-DSS, HIPAA, FedRAMP, or internal data-governance policy), or where you need the ability to instantly revoke decrypt access (e.g., during an incident) by disabling a key, a customer-managed key is required. It also enables cross-account/cross-region data-sharing scenarios that depend on explicit key grants.

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` with `get_expected_value` returning `ANY_VALUE`, inspecting the `kms_key_id` attribute on `aws_redshiftserverless_namespace`. It passes if `kms_key_id` is set to any value, and fails if the attribute is omitted (implying default AWS-managed key encryption).

## Non-compliant example
```hcl
resource "aws_redshiftserverless_namespace" "example" {
  namespace_name = "example-namespace"
  # kms_key_id not set -> uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "redshift_serverless" {
  description         = "CMK for Redshift Serverless namespace"
  enable_key_rotation = true
}

resource "aws_redshiftserverless_namespace" "example" {
  namespace_name = "example-namespace"
  kms_key_id     = aws_kms_key.redshift_serverless.arn
}
```

## Remediation steps
1. Provision a customer-managed KMS key dedicated to the Redshift Serverless namespace, with automatic rotation enabled.
2. Set `kms_key_id` on the `aws_redshiftserverless_namespace` resource to that key's ARN.
3. Attach a key policy granting the Redshift Serverless service principal the required `kms:Decrypt`/`kms:GenerateDataKey`/`kms:CreateGrant` permissions.
4. Be aware that changing the KMS key on an existing namespace may require re-encryption or replacement — verify the AWS provider's behavior for in-place updates versus forced replacement before applying to a namespace already holding data.
5. Apply the same CMK strategy consistently to any associated `aws_redshiftserverless_workgroup` and snapshot resources for end-to-end customer-controlled encryption.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftServerlessNamespaceKMSKey.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-encryption.html
