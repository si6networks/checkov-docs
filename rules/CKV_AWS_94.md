# CKV_AWS_94: Ensure Glue Data Catalog Encryption is enabled

## Severity
**HIGH** (score: 7.5/10)

Disabling encryption on the Glue Data Catalog leaves metadata about data sources, connections, and potentially embedded connection credentials stored and transmitted without protection.

## Summary
This check fails unless an AWS Glue Data Catalog encryption settings resource has *both* connection-password encryption enabled *and* at-rest encryption (SSE-KMS) enabled for the catalog.

## Applicability
- **Terraform**: `aws_glue_data_catalog_encryption_settings` resource — inspects `data_catalog_encryption_settings[0].encryption_at_rest` and `.connection_password_encryption`.
- **CloudFormation**: `AWS::Glue::DataCatalogEncryptionSettings` resource — inspects `Properties.DataCatalogEncryptionSettings.EncryptionAtRest` and `.ConnectionPasswordEncryption`.

## Why it matters
The Glue Data Catalog stores metadata about data sources across an organization's data lake/warehouse — table schemas, S3 locations, and, critically, connection objects that can include credentials for JDBC data stores (databases, warehouses). If the catalog is not encrypted at rest, its metadata (including connection strings/credentials, wherever passwords aren't separately encrypted) sits as plaintext in the underlying storage, exposed to anyone with access to the underlying infrastructure or a misconfigured snapshot/backup. If connection-password encryption (`ReturnConnectionPasswordEncrypted`) is off, database credentials used by Glue crawlers/ETL jobs can be retrieved in plaintext via the Glue API by anyone with `glue:GetConnection` permission — significantly widening who can obtain those credentials beyond just infrastructure-level access. Both settings are cheap, non-disruptive controls (backed by KMS) that meaningfully reduce the blast radius of an over-permissioned IAM policy or a catalog-level access misconfiguration.

## How Checkov evaluates this
Both implementations require two conditions to both be true for a PASS; either single condition missing results in FAIL:
- **`encrypted_at_rest`**: The `EncryptionAtRest`/`encryption_at_rest` block's `CatalogEncryptionMode`/`catalog_encryption_mode` must equal `"SSE-KMS"` (Terraform additionally requires `sse_aws_kms_key_id` to be present).
- **`connection_encrypted`**: The `ConnectionPasswordEncryption`/`connection_password_encryption` block's `ReturnConnectionPasswordEncrypted`/`return_connection_password_encrypted` must be `true` (Terraform additionally requires `aws_kms_key_id` to be present).

Only if both flags end up `true` does the check return PASSED; otherwise FAILED (including if the whole `DataCatalogEncryptionSettings`/`data_catalog_encryption_settings` block is absent).

## Non-compliant example
```hcl
resource "aws_glue_data_catalog_encryption_settings" "catalog" {
  data_catalog_encryption_settings {
    encryption_at_rest {
      catalog_encryption_mode = "DISABLED"
    }
    connection_password_encryption {
      return_connection_password_encrypted = false
    }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "glue" {
  description = "KMS key for Glue Data Catalog encryption"
}

resource "aws_glue_data_catalog_encryption_settings" "catalog" {
  data_catalog_encryption_settings {
    encryption_at_rest {
      catalog_encryption_mode = "SSE-KMS"
      sse_aws_kms_key_id      = aws_kms_key.glue.arn
    }
    connection_password_encryption {
      return_connection_password_encrypted = true
      aws_kms_key_id                         = aws_kms_key.glue.arn
    }
  }
}
```

## Remediation steps
1. Create or designate a KMS key for Glue catalog encryption (a customer-managed key gives you audit and rotation control).
2. Set `encryption_at_rest.catalog_encryption_mode = "SSE-KMS"` with `sse_aws_kms_key_id` pointing at that key.
3. Set `connection_password_encryption.return_connection_password_encrypted = true` with `aws_kms_key_id` pointing at the same (or a separate) key.
4. Grant the Glue service role `kms:Decrypt`/`kms:GenerateDataKey` on the KMS key via its key policy.
5. Note this is an account/region-level singleton setting (one `DataCatalogEncryptionSettings` per catalog) — applying it affects all databases/tables/connections in that catalog, so verify existing crawlers and ETL jobs have the necessary KMS grants before enabling.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GlueDataCatalogEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/GlueDataCatalogEncryption.py
- AWS docs: https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html
