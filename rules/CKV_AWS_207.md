# CKV_AWS_207: Ensure MQ Broker minor version updates are enabled
## Severity
**LOW** (score: 2.0/10)

Disabling automatic minor version updates on an MQ broker means known security fixes in patch releases aren't applied automatically, gradually increasing exposure to already-disclosed vulnerabilities over time.

## Summary
Ensures that Amazon MQ brokers have automatic minor version upgrades enabled, so security patches and bug fixes for the broker engine are applied automatically during maintenance windows.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_mq_broker` — inspects the `auto_minor_version_upgrade` attribute.

## Why it matters
Message broker software (ActiveMQ, RabbitMQ) periodically receives minor-version patches that fix security vulnerabilities (e.g., CVEs in the broker engine, its web console, or bundled libraries) as well as stability bugs. If `auto_minor_version_upgrade` is disabled:
- The broker remains pinned to whatever minor version it was launched with, meaning known vulnerabilities patched upstream are never applied unless someone manually intervenes.
- Operators frequently forget to manually track and apply minor version patches for infrastructure components that "just work," leading to broker fleets running increasingly outdated, unpatched software over time.
- Since MQ brokers often sit in the critical path for inter-service communication, an unpatched vulnerability in the broker itself (e.g., an auth bypass or RCE in the management console) can become a foothold for lateral movement.

## How Checkov evaluates this
`MQBrokerMinorAutoUpgrade` is a `BaseResourceValueCheck` (default expected value `True`, since no `get_expected_value()` override is defined, the base class defaults to expecting the value `True`) inspecting `auto_minor_version_upgrade`:
- If `auto_minor_version_upgrade` is `true` → PASS.
- If `false` or unset (Terraform's own default is actually `true`, but Checkov still flags an explicit `false` or an unresolved/missing value) → FAIL.

## Non-compliant example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name                = "orders-broker"
  engine_type                = "ActiveMQ"
  engine_version              = "5.17.6"
  host_instance_type          = "mq.t3.micro"
  deployment_mode             = "SINGLE_INSTANCE"
  auto_minor_version_upgrade  = false   # FAILS CKV_AWS_207

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediated example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name                = "orders-broker"
  engine_type                = "ActiveMQ"
  engine_version              = "5.17.6"
  host_instance_type          = "mq.t3.micro"
  deployment_mode             = "SINGLE_INSTANCE"
  auto_minor_version_upgrade  = true   # fix

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediation steps
1. Set `auto_minor_version_upgrade = true` on the `aws_mq_broker` resource.
2. Confirm a suitable maintenance window is configured (`maintenance_window_start_time`) during a low-traffic period, since minor upgrades may involve a brief broker restart/failover.
3. For multi-broker (active/standby) deployments, verify failover behavior during the maintenance window won't cause message loss for non-durable subscriptions.
4. This is generally a safe in-place attribute change with no resource replacement required, but the actual upgrade itself happens asynchronously in the next maintenance window, not immediately on apply.
5. Periodically review broker `engine_version` to ensure it's still within AWS's supported version range, since auto minor upgrades won't perform major version jumps.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerMinorAutoUpgrade.py
- AWS docs: https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-maintenance.html
