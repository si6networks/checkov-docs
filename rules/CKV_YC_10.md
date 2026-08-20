# CKV_YC_10: Ensure etcd database is encrypted with KMS key

## Severity
**HIGH** (score: 7.4/10)

Unencrypted etcd storage in a Kubernetes cluster means cluster secrets, service account tokens, and other sensitive control-plane state are persisted in plaintext, giving an attacker with storage/backup access a direct route to cluster compromise.

## Summary
This check fails when a Yandex Managed Service for Kubernetes (`yandex_kubernetes_cluster`) does not configure a KMS key for etcd encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `yandex_kubernetes_cluster`

## Why it matters
Kubernetes etcd is the cluster's primary datastore and holds all cluster state, including Secrets (which frequently contain database credentials, API tokens, TLS private keys, and other sensitive material), ConfigMaps, and full resource definitions. By default, etcd stores this data unencrypted at rest (or with only disk-level encryption that doesn't protect against etcd-level access). If an attacker gains access to the underlying etcd storage volumes/snapshots/backups — through a storage misconfiguration, a compromised node, or an insider — they can read all Secrets in plaintext. Enabling application-layer envelope encryption of etcd data using a KMS-managed key ensures that even if the raw etcd data is exfiltrated, it cannot be decrypted without access to the KMS key, which is typically far more tightly access-controlled and audited (with usage logging) than the etcd storage itself.

## How Checkov evaluates this
The check (`K8SEtcdKMSEncryption`) is a `BaseResourceValueCheck` that inspects the attribute path `kms_provider/[0]/key_id`:
- The expected value is `ANY_VALUE` — any non-empty `key_id` satisfies the check.
- If the cluster configuration includes a `kms_provider` block with a `key_id` set, the check **PASSES**.
- If `kms_provider`/`key_id` is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_cluster" "example" {
  name       = "prod-k8s"
  network_id = yandex_vpc_network.app.id

  master {
    version   = "1.28"
    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.app.id
    }
  }
  # no kms_provider block -- FAILS CKV_YC_10
}
```

## Remediated example
```hcl
resource "yandex_kms_symmetric_key" "etcd_key" {
  name              = "k8s-etcd-encryption-key"
  default_algorithm = "AES_128"
  rotation_period   = "8760h"
}

resource "yandex_kubernetes_cluster" "example" {
  name       = "prod-k8s"
  network_id = yandex_vpc_network.app.id

  master {
    version   = "1.28"
    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.app.id
    }
  }

  kms_provider {
    key_id = yandex_kms_symmetric_key.etcd_key.id  # added -- PASSES CKV_YC_10
  }
}
```

## Remediation steps
1. Create a `yandex_kms_symmetric_key` resource dedicated to Kubernetes etcd encryption.
2. Reference the key's ID in the cluster's `kms_provider { key_id = ... }` block.
3. Enable automatic key rotation (`rotation_period`) on the KMS key for defense-in-depth.
4. Restrict IAM permissions on the KMS key so only the Kubernetes service account/service can use it for decrypt operations.
5. Note: `kms_provider` is generally set at cluster creation time; changing it on an existing cluster may not be supported in-place and could require careful migration — check current Yandex Cloud provider capabilities before attempting on a running production cluster.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SEtcdKMSEncryption.py)
- [Yandex Managed Service for Kubernetes documentation](https://yandex.cloud/en/docs/managed-kubernetes/concepts/)
