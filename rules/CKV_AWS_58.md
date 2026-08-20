# CKV_AWS_58: Ensure EKS Cluster has Secrets Encryption Enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without envelope encryption of Kubernetes Secrets at rest via KMS, sensitive credentials and tokens stored in etcd are only protected by default at-rest encryption and remain exposed to anyone with etcd/backup access.

## Summary
This check verifies that an EKS cluster has envelope encryption configured for Kubernetes Secrets using a KMS key, so that Secret objects are encrypted at rest in etcd beyond the default EKS storage encryption.

## Applicability
- **CloudFormation**: `AWS::EKS::Cluster`, property path `Properties/EncryptionConfig`.
- **Terraform**: `aws_eks_cluster` resource, attribute `encryption_config[0].resources`.

## Why it matters
EKS stores all cluster state, including Kubernetes `Secret` objects, in etcd. By default, EKS-managed etcd is encrypted at the storage-volume level using AWS-managed keys, but this does not provide envelope encryption of Secret data specifically with a customer-managed KMS key, nor does it protect against certain internal AWS access-control boundary and multi-tenant risks that a dedicated CMK-based secrets encryption does. Kubernetes Secrets frequently hold sensitive material — database credentials, API tokens, TLS private keys, service account tokens — and are often only base64-encoded, not encrypted, at the Kubernetes API layer. Enabling `EncryptionConfig` with the `secrets` resource type ensures Secret objects are additionally encrypted at the etcd layer using a customer-managed KMS key, giving you control over key rotation, access policies, and audit logging (via CloudTrail) for who can decrypt cluster secrets, and providing compliance-grade encryption-at-rest guarantees (e.g., for PCI-DSS, HIPAA workloads) that go beyond the platform default.

## How Checkov evaluates this
**CloudFormation** (custom `BaseResourceCheck`): reads `Properties/EncryptionConfig` (a list of encryption config blocks). For each block that has a `Resources` key, it collects that list. PASSES only if at least one of those `Resources` lists contains the string `"secrets"`. FAILS otherwise (including when `EncryptionConfig` is absent).

**Terraform** (`BaseResourceValueCheck`): inspects `encryption_config[0].resources` and expects it to equal `["secrets"]`. PASSES only when the first `encryption_config` block's `resources` list is exactly `["secrets"]`; FAILS if the block is missing or does not include `"secrets"`.

## Non-compliant example
```hcl
resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = var.subnet_ids
  }
  # no encryption_config block -> secrets are not envelope-encrypted with a CMK
}
```

## Remediated example
```hcl
resource "aws_kms_key" "eks" {
  description         = "EKS secrets encryption key"
  enable_key_rotation = true
}

resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = var.subnet_ids
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]   # fixed
  }
}
```

## Remediation steps
1. Create (or designate) a KMS key dedicated to EKS secrets encryption, with key rotation enabled.
2. Add an `encryption_config` block to the `aws_eks_cluster` resource (or `EncryptionConfig` property in CloudFormation) referencing that key, with `resources = ["secrets"]`.
3. Note: this setting can only be added at cluster creation or applied later via an in-place update (AWS supports enabling secrets encryption on existing clusters), but it cannot encrypt Secrets that existed before the setting was enabled — those must be "touched" (e.g., re-applied) to be re-encrypted under the new key.
4. Ensure the EKS cluster IAM role and any user/role needing to decrypt secrets has `kms:Decrypt`/`kms:DescribeKey` permission on the key.
5. Monitor KMS key usage via CloudTrail to audit access to cluster secrets.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EKSSecretsEncryption.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSSecretsEncryption.py)
- [AWS: Enabling secrets encryption on an existing cluster](https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html)
