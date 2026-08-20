# CKV_AWS_80: Ensure MSK Cluster logging is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Missing MSK cluster logging limits visibility into broker-level activity needed to detect unauthorized access or misuse of the Kafka cluster, a detection gap rather than a direct exposure.

## Summary
This check fails when an Amazon MSK (Managed Streaming for Apache Kafka) cluster does not have broker logging enabled to at least one of CloudWatch Logs, Kinesis Data Firehose, or S3.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::MSK::Cluster` (CloudFormation), `aws_msk_cluster` (Terraform)
- **Check type:** resource

## Why it matters
MSK broker logs capture Kafka broker-level events — connection attempts, authentication/authorization decisions, topic/partition administration, and error conditions. Without them, there is no audit trail of who connected to the cluster, which clients accessed which topics, or whether unauthorized clients attempted (and possibly succeeded) to connect. Kafka clusters frequently carry high-value, high-volume event streams (transaction events, clickstreams, inter-service messages) that make them an attractive target for data exfiltration or message injection; the absence of broker logs means such activity would go undetected until downstream symptoms appear, if ever. Logging is also frequently mandated for compliance frameworks governing streaming/event-driven architectures that process regulated data.

## How Checkov evaluates this
- **CloudFormation (`MSKClusterLogging.py`):** Looks at `Properties.LoggingInfo.BrokerLogs`. For each of `CloudWatchLogs`, `Firehose`, `S3`, if that key exists and its `Enabled` field is `True`, the check **PASSES**. If none are enabled (or `LoggingInfo`/`BrokerLogs` is absent), it **FAILS**.
- **Terraform (`MSKClusterLogging.py`):** Looks at `logging_info[0].broker_logs[0]`. For each of `cloudwatch_logs`, `firehose`, `s3`, if that key's `[0].enabled[0]` is `True`, the check **PASSES**. Otherwise (block absent or none of the three destinations enabled) it **FAILS**.
- In both cases, only *one* of the three log destinations needs to be enabled to pass.

## Non-compliant example
```hcl
resource "aws_msk_cluster" "events" {
  cluster_name           = "events-cluster"
  kafka_version           = "3.5.1"
  number_of_broker_nodes  = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.msk.id]
  }
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "msk_broker_logs" {
  name              = "/msk/events-cluster/broker-logs"
  retention_in_days = 90
}

resource "aws_msk_cluster" "events" {
  cluster_name           = "events-cluster"
  kafka_version           = "3.5.1"
  number_of_broker_nodes  = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = var.subnet_ids
    security_groups = [aws_security_group.msk.id]
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk_broker_logs.name
      }
    }
  }
}
```

## Remediation steps
1. Add a `logging_info` block to the `aws_msk_cluster` resource (Terraform) or `LoggingInfo` under `Properties` (CloudFormation).
2. Enable at least one destination inside `broker_logs`: `cloudwatch_logs`, `firehose`, or `s3`. CloudWatch Logs is typically simplest for operational visibility; S3/Firehose may be preferred for long-term retention or downstream analytics pipelines.
3. If using CloudWatch, create the log group ahead of time and reference its name/ARN; ensure MSK's service-linked role has permission to write to it (usually handled automatically by AWS for MSK-managed logging).
4. If using S3, ensure the target bucket policy grants the MSK service permission to deliver logs.
5. This is a non-disruptive, additive configuration; it does not require cluster replacement, though applying it may trigger a rolling update of broker configuration depending on the Terraform provider version.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MSKClusterLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/MSKClusterLogging.py)
- [Amazon MSK broker logs](https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html)
