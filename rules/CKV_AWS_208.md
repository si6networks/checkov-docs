# CKV_AWS_208: Ensure MQ Broker version is current
## Severity
**LOW** (score: 2.0/10)

Running an MQ broker below the minimum supported ActiveMQ/RabbitMQ version risks exposure to known, already-patched vulnerabilities in the older engine release.

## Summary
Ensures that Amazon MQ brokers (and configurations) run an engine version at or above a defined minimum (ActiveMQ 5.17, RabbitMQ 3.11), so brokers aren't left on old engine releases missing security patches.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_mq_broker`, `aws_mq_configuration` — inspects `engine_type` and `engine_version`.

## Why it matters
Older ActiveMQ and RabbitMQ releases have had publicly disclosed vulnerabilities (e.g., deserialization/RCE issues in older ActiveMQ versions, authentication and authorization bugs in older RabbitMQ releases). Pinning brokers to end-of-life or old minor versions means:
- Known CVEs affecting the broker's web console, wire protocol handling, or management API remain unpatched, giving attackers a documented, well-understood attack path.
- AWS eventually stops supporting old engine versions on Amazon MQ, meaning brokers may face forced (potentially disruptive) upgrades or lose vendor support before you're prepared to plan the migration on your own terms.
- Since the broker is often network-reachable from many services, an exploitable vulnerability in an old version has an outsized blast radius across all systems that connect to it.

## How Checkov evaluates this
`MQBrokerVersion` parses `engine_version` with a regex expecting a semantic-ish version string:
1. Extract `engine_type` (`ActiveMQ` or `RabbitMQ`) and `engine_version`.
2. If `engine_version` doesn't match the expected numeric pattern (`\d+\.\d+.\d+`) → `UNKNOWN` (can't evaluate, e.g., using the `LATEST` alias or a variable).
3. Parse the major.minor portion of the version into a tuple for comparison.
4. If engine is `ActiveMQ` and version ≥ `5.17` → PASS.
5. If engine is `RabbitMQ` and version ≥ `3.11` → PASS.
6. Otherwise (version below the minimum, or unrecognized engine type) → FAIL.

## Non-compliant example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.16"   # FAILS CKV_AWS_208 - below 5.17 minimum
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediated example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"   # fix: meets minimum supported version
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediation steps
1. Update `engine_version` to at least `5.17.x` for ActiveMQ or `3.11.x` for RabbitMQ (check AWS's current list of supported engine versions, since these minimums may be superseded by newer Checkov releases as AWS deprecates older ones).
2. Test the version upgrade in a non-production broker first — ActiveMQ/RabbitMQ minor version bumps can occasionally introduce config or protocol behavior changes.
3. Engine version upgrades on `aws_mq_broker` typically apply via the broker's modification API, but larger jumps might require a reboot; check `apply_immediately` behavior and schedule during a maintenance window for production brokers.
4. Keep `engine_version` pinned to a specific value (not "latest") in Terraform so upgrades are deliberate and tracked via code review, rather than silently drifting.
5. If using `aws_mq_configuration`, ensure its `engine_version` is likewise updated and stays in sync with the broker's version, since mismatches can cause configuration application failures.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerVersion.py
- AWS docs: https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html
