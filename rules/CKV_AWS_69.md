# CKV_AWS_69: Ensure Amazon MQ Broker should not have public access
## Severity
**CRITICAL** (score: 9.0/10)

A publicly accessible Amazon MQ broker exposes the messaging endpoint (and any credentials/messages it carries) directly to the internet, allowing unauthorized access to application message queues.

## Summary
This check fails when an Amazon MQ broker is configured with `PubliclyAccessible`/`publicly_accessible` set to `true`, meaning the message broker's endpoints are reachable directly from the public internet rather than only from within the associated VPC.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::AmazonMQ::Broker`, property `Properties/PubliclyAccessible`.
- **Terraform**: `aws_mq_broker` resource, attribute `publicly_accessible`.

## Why it matters
Amazon MQ brokers (ActiveMQ/RabbitMQ) sit in the middle of application messaging architectures and typically carry business-critical, sometimes sensitive, message payloads (order events, financial transactions, PII in transit between services). A publicly accessible broker exposes its network endpoint (and, by extension, its authentication surface — username/password or SASL) directly to internet scanning and brute-force attempts, removing the network-layer isolation that a VPC-private broker provides as a first line of defense. If broker credentials are ever weak, reused, or leaked, public accessibility means the attack surface for exploiting that credential leak is "anyone on the internet" rather than "someone already inside the VPC or connected via VPN/peering." Message brokers are also attractive targets because compromising one can let an attacker intercept, inject, or replay messages across every consuming service downstream — a single broker compromise can cascade into multiple application compromises.

## How Checkov evaluates this
**CloudFormation** (`BaseResourceValueCheck` with `missing_block_result=CheckResult.FAILED`): inspects `Properties/PubliclyAccessible`, expects it to equal `False`. PASSES only if explicitly set to `false`; FAILS if `true` or if the property is missing entirely (fail-closed default, since AWS's underlying default for a new MQ broker is not guaranteed non-public in every SDK/console path).

**Terraform** (`BaseResourceNegativeValueCheck`): inspects `publicly_accessible`, with forbidden value `True`. FAILS if the value is `true`; PASSES if `false` or absent (Terraform's `aws_mq_broker.publicly_accessible` attribute defaults to `false` when unset, so an absent attribute is safely non-public).

## Non-compliant example
```hcl
resource "aws_mq_broker" "orders" {
  broker_name        = "orders-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"
  host_instance_type = "mq.t3.micro"
  publicly_accessible = true    # non-compliant

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediated example
```hcl
resource "aws_mq_broker" "orders" {
  broker_name          = "orders-broker"
  engine_type          = "ActiveMQ"
  engine_version       = "5.17.6"
  host_instance_type   = "mq.t3.micro"
  publicly_accessible  = false            # fixed
  subnet_ids           = [aws_subnet.private_a.id]
  security_groups      = [aws_security_group.mq.id]

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediation steps
1. Set `publicly_accessible = false` (Terraform) or `PubliclyAccessible: false` (CloudFormation) on the broker resource.
2. Deploy the broker into private subnets and connect application clients via VPC peering, Transit Gateway, or Direct Connect/VPN for on-premises consumers.
3. Restrict the broker's security group to only the specific source security groups/CIDR ranges of legitimate producer/consumer applications.
4. **Caveat**: changing `publicly_accessible` on an existing broker typically requires a reboot (and for some engine/instance-type combinations may require replacement) — plan a maintenance window and verify client connection strings will still resolve to the correct (now-private) endpoint.
5. Rotate broker credentials as a precaution if the broker was ever publicly accessible, since it may have been exposed to internet scanning/brute-force attempts.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/AmazonMQBrokerPublicAccess.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerNotPubliclyExposed.py)
- [AWS: Amazon MQ and VPCs](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-vpc.html)
