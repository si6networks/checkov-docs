# CKV_AWS_263: Ensure AppFlow flow uses CMK

## Severity
**LOW** (score: 2.0/10)

AppFlow data in transit between SaaS systems and AWS can include sensitive business data, but the check only enforces customer-managed key usage on top of existing default encryption, so the exposure is reduced key governance and audit granularity rather than plaintext data.

## Summary
This check ensures that an Amazon AppFlow flow specifies a customer-managed KMS key ARN (`kms_arn`) for encrypting data that moves through the flow.

## Applicability
- **Terraform**: resource `aws_appflow_flow`

## Why it matters
AppFlow moves potentially sensitive data between SaaS applications (e.g., Salesforce, Slack, Zendesk) and AWS services (S3, Redshift, etc.). Data in transit through and staged by a flow can include customer PII, support ticket contents, or business records. If encryption relies on the AWS-owned default key rather than a customer-managed key, the organization loses granular control over who can decrypt that data, cannot enforce a distinct key policy or rotation schedule for this specific data flow, and cannot get CloudTrail-level visibility scoped to just this integration's key usage. This matters especially for flows that cross organizational or compliance boundaries (e.g., moving data from a third-party SaaS tool into a regulated environment) where a dedicated audit trail on the encryption key is often a compliance requirement (SOC2, HIPAA, PCI).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` looking at the `kms_arn` attribute:
- **PASS**: `kms_arn` is set to any non-empty value.
- **FAIL**: `kms_arn` is absent or empty.

## Non-compliant example
```hcl
resource "aws_appflow_flow" "salesforce_to_s3" {
  name = "salesforce-sync"

  source_flow_config {
    connector_type = "Salesforce"
    connector_profile_name = aws_appflow_connector_profile.sf.name
    source_connector_properties {
      salesforce {
        object = "Account"
      }
    }
  }

  destination_flow_config {
    connector_type = "S3"
    destination_connector_properties {
      s3 {
        bucket_name = aws_s3_bucket.dest.bucket
      }
    }
  }

  task {
    source_fields     = ["Id", "Name"]
    task_type         = "Filter"
    connector_operator {
      salesforce = "PROJECTION"
    }
  }

  trigger_config {
    trigger_type = "OnDemand"
  }
  # no kms_arn set
}
```

## Remediated example
```hcl
resource "aws_appflow_flow" "salesforce_to_s3" {
  name    = "salesforce-sync"
  kms_arn = aws_kms_key.appflow.arn   # customer-managed key

  source_flow_config {
    connector_type = "Salesforce"
    connector_profile_name = aws_appflow_connector_profile.sf.name
    source_connector_properties {
      salesforce {
        object = "Account"
      }
    }
  }

  destination_flow_config {
    connector_type = "S3"
    destination_connector_properties {
      s3 {
        bucket_name = aws_s3_bucket.dest.bucket
      }
    }
  }

  task {
    source_fields     = ["Id", "Name"]
    task_type         = "Filter"
    connector_operator {
      salesforce = "PROJECTION"
    }
  }

  trigger_config {
    trigger_type = "OnDemand"
  }
}
```

## Remediation steps
1. Create a dedicated CMK for AppFlow (`aws_kms_key` with `enable_key_rotation = true`).
2. Add `kms_arn = aws_kms_key.appflow.arn` to the `aws_appflow_flow` resource.
3. Update the KMS key policy to grant AppFlow's service principal and consuming roles `kms:Decrypt`/`kms:GenerateDataKey`.
4. Ensure the destination service (e.g., S3 bucket, Redshift cluster) also trusts and can use the same key if it needs to decrypt the delivered data.
5. Existing flows may need to be recreated or updated depending on provider version support for in-place `kms_arn` changes; verify against your AWS provider version.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppFlowUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/appflow/latest/userguide/data-protection.html
