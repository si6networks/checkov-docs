# CKV_AWS_367: Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt model artifacts

## Severity
**LOW** (score: 2.0/10)

Without a customer-managed key, monitoring output artifacts still get default S3 encryption but lose independent key-level access control, rotation, and CloudTrail-auditable decrypt visibility over data that may reveal statistical characteristics of production data.

## Summary
This check ensures that an Amazon SageMaker Data Quality Job Definition specifies a customer-managed KMS key for encrypting the output (model monitoring/data quality) artifacts it produces.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::SageMaker::DataQualityJobDefinition` (property `DataQualityJobOutputConfig/KmsKeyId`), `aws_sagemaker_data_quality_job_definition` (attribute `data_quality_job_output_config[0].kms_key_id`)

## Why it matters
SageMaker Data Quality Jobs analyze production inference data to detect drift, schema violations, and statistical anomalies, and they write their output (constraint violations, statistics, drift reports) to S3. This output can reveal sensitive characteristics of production data — feature distributions, PII-adjacent statistics, or business-sensitive signals about model inputs — even without containing raw records. Without a customer-managed KMS key, the output either relies on default S3-managed encryption (SSE-S3) or, in the worst case, no encryption at all, meaning your organization loses control over key rotation, access auditing (via CloudTrail key-usage events), and the ability to revoke access to historical monitoring artifacts independently of the S3 bucket's own IAM controls. Using a CMK enables key-level access policies, detailed CloudTrail logging of every decrypt/encrypt call, and clean separation of duties between who can read the S3 objects and who can use the key to decrypt them.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) using `ANY_VALUE` as the expected value — meaning it doesn't check for a *specific* key, only that `DataQualityJobOutputConfig/KmsKeyId` (`data_quality_job_output_config[0].kms_key_id`) is set to *any* non-empty value. If the field is absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sagemaker_data_quality_job_definition" "drift_monitor" {
  name = "prod-drift-monitor"

  data_quality_job_input {
    endpoint_input {
      endpoint_name = aws_sagemaker_endpoint.prod.name
    }
  }

  data_quality_job_output_config {
    monitoring_outputs {
      s3_output {
        s3_uri = "s3://monitoring-bucket/data-quality/"
      }
    }
    # No kms_key_id set
  }

  job_resources {
    cluster_config {
      instance_count    = 1
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 20
    }
  }

  role_arn = aws_iam_role.sagemaker_monitor.arn
}
```

## Remediated example
```hcl
resource "aws_sagemaker_data_quality_job_definition" "drift_monitor" {
  name = "prod-drift-monitor"

  data_quality_job_input {
    endpoint_input {
      endpoint_name = aws_sagemaker_endpoint.prod.name
    }
  }

  data_quality_job_output_config {
    kms_key_id = aws_kms_key.sagemaker_monitoring.arn

    monitoring_outputs {
      s3_output {
        s3_uri = "s3://monitoring-bucket/data-quality/"
      }
    }
  }

  job_resources {
    cluster_config {
      instance_count    = 1
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 20
    }
  }

  role_arn = aws_iam_role.sagemaker_monitor.arn
}
```

## Remediation steps
1. Create (or identify an existing) customer-managed KMS key intended for SageMaker monitoring output.
2. Set `kms_key_id` inside the `data_quality_job_output_config` block to that key's ARN or ID.
3. Ensure the SageMaker execution role (`role_arn`) has `kms:GenerateDataKey` and `kms:Decrypt` permissions on the key, and that the key policy grants access to that role.
4. This is typically set at creation time for the job definition — Data Quality Job Definitions are largely immutable once created, so changing this after the fact may require creating a new job definition and updating the monitoring schedule to reference it.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerDataQualityJobDefinitionEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerDataQualityJobDefinitionEncryption.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-byoc-encryption.html
