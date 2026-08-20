# CKV_AWS_369: Ensure Amazon Sagemaker Data Quality Job encrypts all communications between instances used for monitoring jobs

## Severity
**LOW** (score: 2.0/10)

Unencrypted inter-container traffic exposes data derived from production inference (potentially PII or business-sensitive) to sniffing by anyone with network-path access, but exploitation requires an additional foothold on the shared VPC/network rather than being directly reachable from outside.

## Summary
This check ensures that an Amazon SageMaker Data Quality Job Definition enables inter-container traffic encryption, so that network traffic between the distributed compute instances running the monitoring job is encrypted in transit.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::SageMaker::DataQualityJobDefinition` (property `NetworkConfig/EnableInterContainerTrafficEncryption`), `aws_sagemaker_data_quality_job_definition` (attribute `network_config[0].enable_inter_container_traffic_encryption`)

## Why it matters
When a SageMaker Data Quality Job runs on multiple instances (a distributed cluster), the instances exchange data — including chunks of the production inference data being analyzed and intermediate statistical results — over the internal VPC network. Without inter-container traffic encryption, this traffic traverses the network in plaintext. In a multi-tenant or shared-VPC environment, or if an attacker gains a foothold anywhere on the network path (e.g., via a compromised instance, misconfigured security group, or a rogue ENI), that data could be sniffed. Since this data may include information derived from real production traffic (potentially containing PII or business-sensitive signals), the confidentiality of these internal transfers matters as much as encryption of the job's stored input/output.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) inspecting `NetworkConfig/EnableInterContainerTrafficEncryption` (`network_config[0].enable_inter_container_traffic_encryption`). No custom `get_expected_value()` is overridden, so it uses the framework default expected value of `true`. If the field is absent or `false`, the check **FAILS**.

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
      instance_count    = 2
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 20
    }
  }

  network_config {
    enable_inter_container_traffic_encryption = false
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
      instance_count    = 2
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 20
    }
  }

  network_config {
    enable_inter_container_traffic_encryption = true
  }

  role_arn = aws_iam_role.sagemaker_monitor.arn
}
```

## Remediation steps
1. Add or set `enable_inter_container_traffic_encryption = true` inside the `network_config` block.
2. Be aware this can increase job runtime for jobs with heavy inter-node communication, since traffic is now encrypted/decrypted; budget for a modest overhead, especially with larger instance counts.
3. Data Quality Job Definitions are effectively immutable once created — this needs to be set at creation time; changing it later requires creating a new job definition and updating the associated monitoring schedule.
4. Combine with `network_config.enable_network_isolation` where feasible for further containment of the monitoring job's network access.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerDataQualityJobDefinitionTrafficEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerDataQualityJobDefinitionTrafficEncryption.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/train-encrypt.html
