# CKV_AWS_291: Ensure MSK nodes are private
## Severity
**HIGH** (score: 7.5/10)

An MSK cluster with public broker access exposes the Kafka message bus directly to the internet, allowing unauthorized network reachability to potentially sensitive streaming data and cluster management endpoints.

## Summary
This check fails when an Amazon MSK (Managed Streaming for Kafka) cluster's broker nodes are configured with public connectivity via AWS-provided Elastic IPs (`PublicAccess.Type = "SERVICE_PROVIDED_EIPS"`), exposing Kafka brokers directly to the internet.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** Terraform, CloudFormation
- **Resources:** `aws_msk_cluster` (Terraform), `AWS::MSK::Cluster` (CloudFormation)

## Why it matters
MSK broker nodes configured with `SERVICE_PROVIDED_EIPS` public access are assigned public IP addresses reachable from the internet, exposing the Kafka protocol port(s) outside the VPC boundary. Kafka brokers are not designed to be safely internet-facing by default — they typically rely on network-layer isolation (VPC/security groups) as a primary control, and expect authentication/authorization (SASL/IAM/TLS mutual auth) to be layered correctly for any exposure beyond the private network. A publicly reachable broker significantly increases the attack surface: it can be targeted by internet-wide scanning for exposed Kafka instances, subjected to brute-force or protocol-level exploitation attempts, and — if authentication is weak or misconfigured — allow unauthorized producers/consumers to read or inject messages into topics carrying potentially sensitive streaming data (event streams, transaction logs, telemetry). Keeping brokers private and requiring VPN/Direct Connect/PrivateLink or bastion access enforces defense-in-depth even when application-layer auth is properly configured.

## How Checkov evaluates this
**Terraform:** `BaseResourceNegativeValueCheck` inspects the attribute path `broker_node_group_info/[0]/connectivity_info/[0]/public_access/[0]/type` on `aws_msk_cluster`. It fails if that value equals the forbidden value `"SERVICE_PROVIDED_EIPS"`; any other value (or the attribute being absent, which defaults to private/`DISABLED`) passes.

**CloudFormation:** `BaseResourceNegativeValueCheck` inspects `Properties/BrokerNodeGroupInfo/ConnectivityInfo/PublicAccess/Type` on `AWS::MSK::Cluster` with the same forbidden value.

## Non-compliant example
```hcl
resource "aws_msk_cluster" "example" {
  cluster_name           = "example-cluster"
  kafka_version           = "3.5.1"
  number_of_broker_nodes  = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = [aws_subnet.private_a.id, aws_subnet.private_b.id, aws_subnet.private_c.id]
    security_groups = [aws_security_group.msk.id]

    connectivity_info {
      public_access {
        type = "SERVICE_PROVIDED_EIPS"
      }
    }
  }
}
```

## Remediated example
```hcl
resource "aws_msk_cluster" "example" {
  cluster_name           = "example-cluster"
  kafka_version           = "3.5.1"
  number_of_broker_nodes  = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = [aws_subnet.private_a.id, aws_subnet.private_b.id, aws_subnet.private_c.id]
    security_groups = [aws_security_group.msk.id]

    connectivity_info {
      public_access {
        type = "DISABLED"
      }
    }
  }
}
```

## Remediation steps
1. Set `public_access.type = "DISABLED"` (Terraform) or omit/set the equivalent CloudFormation property to disabled, so brokers only receive private VPC IPs.
2. Ensure client subnets are private subnets (no route to an internet gateway) and that connectivity for legitimate external producers/consumers goes through a VPN, AWS Direct Connect, VPC peering, or AWS PrivateLink instead.
3. Confirm security groups on the cluster restrict inbound Kafka ports (9092/9094/9096/2181 as applicable) to only the specific application/VPC CIDR ranges that need access.
4. If public access was previously enabled and is being disabled, note this can require broker replacement/restart depending on Kafka/MSK version — plan for a maintenance window and verify client connectivity is re-established via the private path before considering the change complete.
5. Layer in-transit encryption (TLS) and proper client authentication (SASL/SCRAM or IAM access control) regardless of network exposure, as defense-in-depth beyond just disabling public access.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MSKClusterNodesArePrivate.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/MSKClusterNodesArePrivate.py
- AWS docs: https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html
