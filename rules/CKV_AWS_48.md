# CKV_AWS_48: Ensure MQ Broker logging is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Missing MQ broker logging removes visibility needed to detect and investigate abuse of the messaging service, a detective-control gap rather than a direct exploitation path.

## Summary
This check ensures Amazon MQ brokers have general logging enabled so broker activity is captured for audit and troubleshooting.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_mq_broker`

## Why it matters
Amazon MQ (ActiveMQ/RabbitMQ) brokers handle message queuing that is often a critical, security-relevant integration point between services — carrying authentication events, transaction messages, or orchestration commands. Without general logging enabled, there is no CloudWatch Logs trail of broker-level activity (connections, errors, general operational events), which severely hampers incident response and forensic investigation if the broker is compromised, misused, or experiences an outage. It also removes visibility needed to detect anomalous connection patterns (e.g., a compromised credential being used to drain or flood queues) or to meet audit-logging requirements common in compliance frameworks.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` against `aws_mq_broker`, inspecting the `logs[0].general` attribute:
- **PASS** if `logs { general = true }` is set.
- **FAIL** if the `logs` block is absent, or `general` is `false`/unset.

## Non-compliant example
```hcl
resource "aws_mq_broker" "example" {
  broker_name        = "example-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  user {
    username = "admin"
    password = var.mq_password
  }
  # logs block not set -> general logging disabled
}
```

## Remediated example
```hcl
resource "aws_mq_broker" "example" {
  broker_name        = "example-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  user {
    username = "admin"
    password = var.mq_password
  }

  logs {
    general = true
  }
}
```

## Remediation steps
1. Add a `logs` block to the `aws_mq_broker` resource with `general = true`.
2. Optionally also enable `audit = true` in the same block for ActiveMQ brokers (audit logging captures broker security events specifically), depending on your compliance needs and log volume/cost tolerance.
3. Ensure the associated CloudWatch Logs log group has an appropriate retention policy and, if handling sensitive data, restricted IAM read access.
4. This change can typically be applied to an existing broker without replacement — verify with `terraform plan`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerLogging.py)
- [AWS MQ logging documentation](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-logging-monitoring-CloudWatchLogs.html)
