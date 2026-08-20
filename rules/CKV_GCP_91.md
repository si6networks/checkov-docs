# CKV_GCP_91: Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

Dataproc cluster data is encrypted at rest by default, so missing CMK configuration is a key-management control gap rather than an absence of encryption.

## Summary
This check requires `google_dataproc_cluster` resources to set `cluster_config.encryption_config.kms_key_name`, so that cluster disks and job data are encrypted at rest with a customer-managed Cloud KMS key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_dataproc_cluster`
- **Check type:** resource (attribute-value check on a nested block path)

## Why it matters
Dataproc clusters run Hadoop/Spark workloads over potentially large volumes of business data, and cluster VMs persist intermediate/spill data and logs to local and attached persistent disks. Without a customer-managed key, this at-rest data relies solely on Google's default encryption, which the organization cannot independently rotate, audit, or revoke. For big-data processing environments — often handling aggregated or sensitive datasets across many source systems — CMEK provides a consistent key-custody boundary and an emergency mechanism to cut off access to processed data (e.g., during incident response or data-lifecycle/decommissioning requirements), and is frequently a hard requirement in regulated environments that mandate customer control of encryption keys for any compute handling sensitive data.

## How Checkov evaluates this
The check (`DataprocClusterEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the attribute path `cluster_config/[0]/encryption_config/[0]/kms_key_name` on `google_dataproc_cluster`, checking against `ANY_VALUE`.
- **PASS**: `cluster_config.encryption_config.kms_key_name` is set to any non-empty value.
- **FAIL**: the `encryption_config` block, or its `kms_key_name`, is absent/empty.

## Non-compliant example
```hcl
resource "google_dataproc_cluster" "analytics" {
  name   = "analytics-cluster"
  region = "us-central1"

  cluster_config {
    master_config {
      num_instances = 1
      machine_type  = "n1-standard-4"
    }
    worker_config {
      num_instances = 2
      machine_type  = "n1-standard-4"
    }
    # No encryption_config -> Google-managed encryption only
  }
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "dataproc" {
  name     = "dataproc-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "dataproc" {
  name     = "dataproc-key"
  key_ring = google_kms_key_ring.dataproc.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_dataproc_cluster" "analytics" {
  name   = "analytics-cluster"
  region = "us-central1"

  cluster_config {
    master_config {
      num_instances = 1
      machine_type  = "n1-standard-4"
    }
    worker_config {
      num_instances = 2
      machine_type  = "n1-standard-4"
    }

    encryption_config {
      kms_key_name = google_kms_crypto_key.dataproc.id
    }
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Dataproc cluster.
2. Grant the Dataproc service agent / Compute Engine service account used by the cluster nodes `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key (Dataproc CMEK requires the *Compute Engine* service account, not a Dataproc-specific service agent, to have this role).
3. Add the `encryption_config { kms_key_name = ... }` block inside `cluster_config`.
4. This setting is only applicable at cluster creation; changing it on an existing cluster requires recreating the cluster — plan for job migration/downtime.
5. Confirm the target region supports Dataproc CMEK and that the KMS key and cluster reside in the same region (cross-region CMEK is not supported).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataprocClusterEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/customer-managed-encryption
