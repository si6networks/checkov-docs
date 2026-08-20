# CKV_AWS_81: Ensure MSK Cluster encryption in rest and transit is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Disabling encryption in transit and at rest for an MSK cluster exposes potentially sensitive streamed data to interception on the wire and to disclosure from underlying storage.

## Summary
This check fails when an Amazon MSK cluster either has no `encryption_info`/`EncryptionInfo` configuration at all, or its in-transit encryption settings allow non-TLS broker communication or disable inter-broker cluster encryption.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::MSK::Cluster` (CloudFormation), `aws_msk_cluster` (Terraform)
- **Check type:** resource

## Why it matters
Kafka clusters transport high volumes of business event data between producers, brokers, and consumers, often across VPC/AZ boundaries. If `ClientBroker` encryption is not set to `TLS` (e.g., left as `TLS_PLAINTEXT` or `PLAINTEXT`), producer/consumer traffic can be sent or accepted unencrypted over the network, exposing message contents and potentially SASL/IAM authentication material to anyone able to observe network traffic (e.g., a compromised host in the same VPC, a misconfigured network ACL, or an insider with network tap access). Similarly, if `InCluster` (broker-to-broker replication traffic) encryption is disabled, inter-broker replication of partition data travels in plaintext, which is a particular risk in multi-AZ deployments where that traffic traverses AZ boundaries. Because MSK cluster resource is unencrypted-at-rest by default unless `EncryptionInfo` is specified at all, and Checkov also treats a completely absent block as a hard fail, this check enforces baseline encryption for both data-at-rest (implicitly, via requiring the block) and data-in-transit.

## How Checkov evaluates this
Both implementations share nearly identical logic:
- If no `encryption_info`/`EncryptionInfo` block exists at all → **FAIL** (note: the code comment explains that merely having `EncryptionInfo` present guarantees encryption at rest even without an explicit KMS key, but its absence entirely is still a failure).
- If `encryption_info` is present, inspect `encryption_in_transit`:
  - If `client_broker` is present and **not equal to `"TLS"`** → **FAIL** (e.g., `"TLS_PLAINTEXT"` or `"PLAINTEXT"` both fail).
  - If `in_cluster` is present and **is `false`** → **FAIL**.
  - Otherwise → **PASS**.
- If `encryption_in_transit` is absent entirely (but `encryption_info` exists), the check still **PASSES** in the Terraform version — AWS defaults `client_broker` to `TLS` and `in_cluster` to `true` when the sub-block is omitted.

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

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
      in_cluster     = true
    }
  }
}
```

## Remediated example
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

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

    encryption_in_transit {
      client_broker = "TLS"
      in_cluster     = true
    }
  }
}
```

## Remediation steps
1. Add an `encryption_info` block to the cluster resource — its mere presence guarantees at-rest encryption of broker storage.
2. Within it, add an `encryption_in_transit` block setting `client_broker = "TLS"` to require TLS for all producer/consumer connections (rejecting plaintext clients).
3. Ensure `in_cluster = true` (or simply omit it, since `true` is the default) so broker-to-broker replication traffic is also encrypted.
4. Optionally set `encryption_at_rest_kms_key_arn` to use a customer-managed KMS key for storage encryption instead of the AWS-managed default.
5. **Caveat:** changing `client_broker` on an existing cluster from `TLS_PLAINTEXT`/`PLAINTEXT` to `TLS` requires all client applications to support and use TLS connections — plan a coordinated client-side rollout, since MSK client-broker encryption changes typically require an update via the AWS API/console and may involve a cluster configuration update (check current provider behavior — this can be a disruptive change requiring broker restarts).

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MSKClusterEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/MSKClusterEncryption.py)
- [Amazon MSK encryption documentation](https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html)
