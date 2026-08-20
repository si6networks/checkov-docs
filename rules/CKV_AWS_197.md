# CKV_AWS_197: Ensure MQ Broker Audit logging is enabled
## Severity
**LOW** (score: 2.0/10)

Disabled audit logging on an MQ broker removes the security-relevant trail needed to detect unauthorized access to or misuse of a message broker that often carries sensitive application data.

## Summary
Ensures that Amazon MQ brokers have audit logging enabled so that administrative and connection-level events on the broker are recorded to CloudWatch Logs.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_mq_broker` — inspects `logs[0].audit`.
- **CloudFormation**: `AWS::AmazonMQ::Broker` — inspects `Properties/Logs/Audit`.
- Applies only to `ActiveMQ`-engine brokers; if `EngineType`/`engine_type` is `RabbitMQ`, the check returns `UNKNOWN` (skipped) because RabbitMQ brokers do not support audit logging on Amazon MQ.

## Why it matters
Audit logs on an Amazon MQ (ActiveMQ) broker record security-relevant events such as authentication attempts, connection/disconnection, and administrative changes to the broker. Without them:
- There is no forensic trail to detect brute-force login attempts or unauthorized administrative changes against the broker.
- Incident response after a suspected compromise of a queue/topic used for sensitive workloads (e.g., payment processing, order pipelines) has no audit evidence to work from.
- Compliance frameworks that require logging of access to messaging infrastructure (PCI-DSS 10.x, SOC 2 monitoring controls) are not satisfied.

Since message brokers often sit at the center of decoupled architectures and can carry sensitive payloads, losing visibility into who connected/administered the broker is a meaningful detection gap.

## How Checkov evaluates this
`MQBrokerAuditLogging` extends `BaseResourceValueCheck`:
1. First it checks the broker's `engine_type`. If it equals `"RabbitMQ"` (case-insensitive in CloudFormation; exact list match `["RabbitMQ"]` in Terraform), the check short-circuits and returns `UNKNOWN` — RabbitMQ brokers on Amazon MQ don't support audit logging, so the check doesn't apply.
2. Otherwise (ActiveMQ), it falls through to the base value check, which inspects:
   - Terraform: `logs[0].audit` must be truthy (`true`) → PASS; `false`/absent → FAIL.
   - CloudFormation: `Properties/Logs/Audit` must be truthy → PASS; absent/false → FAIL.

## Non-compliant example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
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
    audit   = false   # FAILS CKV_AWS_197
  }
}
```

## Remediated example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
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
    audit   = true   # fix: audit logging enabled
  }
}
```

## Remediation steps
1. For `ActiveMQ` engine brokers, set `logs { audit = true }` (Terraform) or `Properties.Logs.Audit: true` (CloudFormation).
2. Confirm a CloudWatch Logs log group exists / is auto-created and configure appropriate retention (`aws_cloudwatch_log_group` retention policy) to control cost and compliance retention windows.
3. If using RabbitMQ engine, this control does not apply — rely on RabbitMQ's own logging/management plugin and CloudWatch general logs instead.
4. Grant the broker's service-linked role or IAM permissions needed to write to CloudWatch Logs if using a custom IAM configuration.
5. Enabling logging on an existing broker typically applies without downtime, but confirm via a maintenance window if the broker is in production and sensitive to config-apply reboots.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/MQBrokerAuditLogging.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerAuditLogging.py
- AWS docs: https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/security-logging-monitoring-rabbitmq.html
