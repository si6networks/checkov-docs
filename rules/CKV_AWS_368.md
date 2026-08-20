# CKV_AWS_368: Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt data on attached storage volume

## Severity
**LOW** (score: 2.0/10)

Lacking a CMK for the job's transient EBS storage weakens key-level access auditing and revocation for temporarily-held production data samples, a control gap rather than a directly exploitable exposure.

## Summary
This check ensures that an Amazon SageMaker Data Quality Job Definition specifies a customer-managed KMS key to encrypt the EBS storage volume attached to the monitoring job's compute instances.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::SageMaker::DataQualityJobDefinition` (property `JobResources/ClusterConfig/VolumeKmsKeyId`), `aws_sagemaker_data_quality_job_definition` (attribute `job_resources[0].cluster_config[0].volume_kms_key_id`)

## Why it matters
SageMaker Data Quality Jobs spin up ML instances that pull down production inference data (or samples of it) onto local EBS storage volumes to run statistical analysis. That volume can transiently hold copies of sensitive production data during the job's execution. If the volume isn't encrypted with a customer-managed key, the data at rest on that ephemeral storage relies on default/no encryption controls outside your organization's key management — meaning you lose the ability to audit key usage via CloudTrail, enforce key-level access policies, or immediately revoke decrypt access if the underlying instance or its EBS snapshot is ever exposed (e.g., through misconfigured snapshot sharing or an AWS-side incident). This is particularly important since SageMaker instances are often shared/pooled infrastructure and any volume snapshots taken accidentally could otherwise be more broadly accessible.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) using `ANY_VALUE` — it only verifies that `JobResources/ClusterConfig/VolumeKmsKeyId` (`job_resources[0].cluster_config[0].volume_kms_key_id`) is set to *some* non-empty value, not a specific key. If absent, the check **FAILS**.

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
  }

  job_resources {
    cluster_config {
      instance_count    = 1
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 20
      # No volume_kms_key_id set
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
    monitoring_outputs {
      s3_output {
        s3_uri = "s3://monitoring-bucket/data-quality/"
      }
    }
  }

  job_resources {
    cluster_config {
      instance_count      = 1
      instance_type        = "ml.m5.xlarge"
      volume_size_in_gb    = 20
      volume_kms_key_id    = aws_kms_key.sagemaker_monitoring.arn
    }
  }

  role_arn = aws_iam_role.sagemaker_monitor.arn
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key for encrypting SageMaker job storage volumes.
2. Set `volume_kms_key_id` inside `job_resources.cluster_config` to that key's ARN.
3. Ensure the SageMaker execution role has `kms:CreateGrant`, `kms:Decrypt`, and `kms:GenerateDataKey` permissions on the key.
4. Data Quality Job Definitions are effectively immutable once created — changing this typically requires creating a new job definition and repointing the associated monitoring schedule.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerDataQualityJobDefinitionVolumeEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerDataQualityJobDefinitionVolumeEncryption.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html
