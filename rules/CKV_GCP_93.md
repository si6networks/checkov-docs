# CKV_GCP_93: Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

Spanner databases are encrypted by default, so missing CMK configuration reduces customer control over key rotation/access for the underlying database rather than removing encryption.

## Summary
This check requires `google_spanner_database` resources to set `encryption_config.kms_key_name`, so Cloud Spanner database data at rest is encrypted with a customer-managed Cloud KMS key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_spanner_database`
- **Check type:** resource (attribute-value check on the nested `encryption_config` block)

## Why it matters
Cloud Spanner is typically used for globally-distributed, transactional, mission-critical data (financial ledgers, inventory, session/state stores) that often carries strict data-protection requirements. Relying only on Google-managed encryption means the organization has no independent control over the key protecting this data — no custom rotation schedule, no ability to restrict who can manage the key separately from who can query the database, and no rapid, cryptographic way to revoke access to data at rest. CMEK closes this gap: it lets the organization enforce its own key-management policy, produces an audit trail in Cloud KMS distinct from Spanner's own IAM/audit logs, and provides a decisive incident-response lever (disable the key to make the database's stored data unreadable) independent of database-level access controls.

## How Checkov evaluates this
The check (`SpannerDatabaseEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the attribute path `encryption_config/[0]/kms_key_name` on `google_spanner_database`, checking against `ANY_VALUE`.
- **PASS**: `encryption_config.kms_key_name` is set to a non-empty value.
- **FAIL**: `encryption_config` or its `kms_key_name` is absent/empty.

## Non-compliant example
```hcl
resource "google_spanner_instance" "main" {
  name         = "main-instance"
  config       = "regional-us-central1"
  display_name = "Main Instance"
  num_nodes    = 1
}

resource "google_spanner_database" "orders" {
  instance = google_spanner_instance.main.name
  name     = "orders-db"
  ddl      = ["CREATE TABLE orders (id INT64) PRIMARY KEY(id)"]
  # No encryption_config -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "spanner" {
  name     = "spanner-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "spanner" {
  name     = "spanner-key"
  key_ring = google_kms_key_ring.spanner.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_spanner_instance" "main" {
  name         = "main-instance"
  config       = "regional-us-central1"
  display_name = "Main Instance"
  num_nodes    = 1
}

resource "google_spanner_database" "orders" {
  instance = google_spanner_instance.main.name
  name     = "orders-db"
  ddl      = ["CREATE TABLE orders (id INT64) PRIMARY KEY(id)"]

  encryption_config {
    kms_key_name = google_kms_crypto_key.spanner.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Spanner instance's configuration (regional or multi-region matching the instance config).
2. Grant the Spanner service agent (`service-<PROJECT_NUMBER>@gcp-sa-spanner.iam.gserviceaccount.com`) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Add the `encryption_config { kms_key_name = ... }` block to the database resource.
4. CMEK for Spanner must be set at database-creation time and cannot be added to an existing database — you'll need to create a new CMEK-enabled database and migrate data (e.g., via Dataflow, export/import, or dual-write cutover), which requires careful downtime/consistency planning for a live transactional system.
5. Verify your Spanner instance configuration supports CMEK (regional configs are supported; check current multi-region support before planning).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/SpannerDatabaseEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/spanner/docs/cmek
