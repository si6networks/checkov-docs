# CKV2_AWS_55: Ensure AWS EMR cluster is configured with security configuration
## Severity
**LOW** (score: 2.0/10)

An EMR cluster without a security configuration attached typically lacks at-rest/in-transit encryption and authentication controls for the cluster, exposing potentially sensitive processed data.

## Summary
This check fails when an `aws_emr_cluster` resource has no `security_configuration` attribute set, meaning the cluster runs without EMR's centralized encryption/authentication/authorization security configuration applied.

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_emr_cluster`

## Why it matters
EMR's `security_configuration` object is the mechanism that enables encryption at rest (for EBS volumes and S3 data via SSE-S3/SSE-KMS/CSE-KMS/CSE-Custom), encryption in transit (TLS between cluster nodes for Hadoop/Spark shuffle traffic and other in-cluster communication), and integration with Kerberos authentication/IAM roles for EMRFS authorization. Without a security configuration attached, an EMR cluster processing data — which is frequently large-scale analytics jobs touching sensitive datasets pulled from S3 — leaves that data unencrypted both while sitting on cluster-local/EBS storage and while being shuffled between nodes over the cluster's internal network. In a shared or multi-tenant VPC, or in the event any cluster node is compromised, this exposes the plaintext data being processed, along with intermediate/shuffle data, to anyone with network visibility into the cluster or access to its underlying storage.

## How Checkov evaluates this
This is a graph-based JSON policy checking a single attribute:
- **Attribute checked:** `security_configuration` on `aws_emr_cluster`
- **Operator:** `exists`
- **PASS** if `security_configuration` references any `aws_emr_security_configuration` resource (or inline JSON).
- **FAIL** if the attribute is absent entirely.
- Note: the check only confirms *a* security configuration is attached — it does not itself validate the contents of that configuration (e.g. whether encryption is actually turned on within it, or which KMS key is used). A cluster could technically pass this check with a security configuration that has weak settings inside it; review the referenced configuration's JSON body separately.

## Non-compliant example
```hcl
resource "aws_emr_cluster" "bad" {
  name          = "analytics-cluster"
  release_label = "emr-6.15.0"
  applications  = ["Spark"]

  ec2_attributes {
    subnet_id = aws_subnet.private.id
  }

  master_instance_group {
    instance_type = "m5.xlarge"
  }

  core_instance_group {
    instance_type  = "m5.xlarge"
    instance_count = 2
  }

  service_role = aws_iam_role.emr_service.arn
  # no security_configuration
}
```

## Remediated example
```hcl
resource "aws_emr_security_configuration" "encryption" {
  name = "emr-encryption-config"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = true
      EnableAtRestEncryption    = true
      InTransitEncryptionConfiguration = {
        TLSCertificateConfiguration = {
          CertificateProviderType = "PEM"
          S3Object                = "s3://example-bucket/certs.zip"
        }
      }
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-KMS"
          AwsKmsKey      = aws_kms_key.emr.arn
        }
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "AwsKms"
          AwsKmsKey                 = aws_kms_key.emr.arn
        }
      }
    }
  })
}

resource "aws_emr_cluster" "good" {
  name                 = "analytics-cluster"
  release_label        = "emr-6.15.0"
  applications         = ["Spark"]
  security_configuration = aws_emr_security_configuration.encryption.name

  ec2_attributes {
    subnet_id = aws_subnet.private.id
  }

  master_instance_group {
    instance_type = "m5.xlarge"
  }

  core_instance_group {
    instance_type  = "m5.xlarge"
    instance_count = 2
  }

  service_role = aws_iam_role.emr_service.arn
}
```

## Remediation steps
1. Create an `aws_emr_security_configuration` resource with an `EncryptionConfiguration` block enabling both `EnableAtRestEncryption` and `EnableInTransitEncryption`.
2. For at-rest encryption, configure `S3EncryptionConfiguration` (prefer `SSE-KMS` with a customer-managed KMS key) and `LocalDiskEncryptionConfiguration` for EBS/local storage.
3. For in-transit encryption, provide a `TLSCertificateConfiguration` (certificates can be self-managed via a zipped PEM bundle in S3, or via a custom certificate provider).
4. Reference the security configuration's `name` via the `security_configuration` attribute on the `aws_emr_cluster`.
5. `security_configuration` cannot be changed on a running cluster — it's set at cluster creation time, so applying this to an existing cluster requires provisioning a new cluster with the security configuration attached and migrating workloads, rather than an in-place update.
6. If Kerberos-based authentication is also required, add a `KerberosAttributes` block to the security configuration and cluster.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EMRClusterHasSecurityConfiguration.json
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html
