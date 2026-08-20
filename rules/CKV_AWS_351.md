# CKV_AWS_351: Ensure EMR Cluster security configuration encrypts InTransit
## Severity
**LOW** (score: 2.0/10)

Without in-transit encryption between EMR cluster nodes, data shuffled between mappers/reducers or transferred within the cluster network can be intercepted by anyone with access to the VPC traffic path.

## Summary
Ensures an EMR security configuration enables in-transit (TLS) encryption for data moving between cluster nodes.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_emr_security_configuration`

## Why it matters
EMR clusters distribute work across many nodes, constantly exchanging data over the network — HDFS block transfers, YARN shuffle data between mappers and reducers, RPC calls between the ResourceManager/NodeManagers, and application-framework traffic (Spark shuffle, Presto/Trino exchange, etc.). Without in-transit encryption enabled, all of this inter-node traffic travels in cleartext across the cluster's VPC subnet. Any entity with the ability to observe that network segment — a compromised node in the same subnet/security group, a misconfigured VPC peering/mirroring setup, or an insider with packet-capture access — could intercept sensitive data as it moves between nodes, even if the cluster's storage (S3, EBS, local disk) is separately encrypted at rest. This is especially significant for multi-tenant or shared-VPC EMR deployments where network-level isolation may not be airtight.

## How Checkov evaluates this
The check reads `configuration[0]` and searches (via a recursive dict lookup) for the key path `EncryptionConfiguration/EnableInTransitEncryption`:
- **PASS**: that path resolves to a truthy value (in-transit encryption enabled — this covers open-source TLS-based encryption for RPC, HTTP, and shuffle traffic within the cluster).
- **FAIL**: the path is missing or falsy.
- **UNKNOWN**: the `configuration` attribute is missing or not a parseable list.

Note this check does not require a specific certificate provider type (e.g. `PEM`), only that `EnableInTransitEncryption` itself is set to `true` somewhere under `EncryptionConfiguration`.

## Non-compliant example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-no-in-transit"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption = true
      # EnableInTransitEncryption not set -> inter-node traffic is cleartext
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-S3"
        }
      }
    }
  })
}
```

## Remediated example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-in-transit-encrypted"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = true
      EnableAtRestEncryption    = true
      InTransitEncryptionConfiguration = {
        TLSCertificateConfiguration = {
          CertificateProviderType = "PEM"
          S3Object                = "s3://my-emr-certs/certs.zip"
        }
      }
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-S3"
        }
      }
    }
  })
}
```

## Remediation steps
1. Locate every `aws_emr_security_configuration` resource in your Terraform code.
2. Add `EnableInTransitEncryption = true` under `EncryptionConfiguration`.
3. Provide the required `InTransitEncryptionConfiguration.TLSCertificateConfiguration` — EMR needs a certificate bundle (PEM files or a custom certificate provider) supplied via an S3 object or custom KMS-based provider for TLS between nodes.
4. Because EMR security configurations are immutable, create a new resource (new name) with in-transit encryption enabled and point `aws_emr_cluster.security_configuration` to it; existing running clusters must be replaced/relaunched to pick it up.
5. Test cluster bootstrap carefully — misconfigured or missing certificates can cause cluster launch failures; validate in a non-production EMR cluster first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRClusterConfEncryptsInTransit.py
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html
