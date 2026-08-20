# CKV_GCP_121: Ensure BigQuery tables have deletion protection enabled

## Severity
**MEDIUM** (score: 5.0/10)

Missing deletion protection on a BigQuery table is chiefly an accidental-deletion/data-loss risk rather than an exploitable confidentiality or access-control weakness.

## Summary
This check requires `google_bigquery_table` resources to explicitly set `deletion_protection = true`, preventing accidental or unauthorized deletion of BigQuery tables via Terraform.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_bigquery_table`
- **Check type:** resource (value check)

## Why it matters
BigQuery tables frequently hold large volumes of analytical data, logs, or aggregated business data that can be expensive or impossible to reconstruct if deleted (e.g., external log sinks, historical telemetry, or one-time batch imports). Terraform is declarative: a resource rename, a module refactor that changes a resource's address, an accidental `terraform destroy`, or a bad merge that removes a `resource` block can all result in Terraform deleting the table on the next apply. `deletion_protection` forces an explicit, separate step before the underlying table can be destroyed, adding a deliberate checkpoint against irreversible data loss — particularly important for tables backing compliance, audit, or analytics pipelines where the data cannot simply be re-ingested from source.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `deletion_protection`
- **Expected value:** `true`
- **`missing_block_result`** is explicitly set to `CheckResult.FAILED` — if the attribute is absent entirely, the check treats the table as unprotected and **FAILS** (this differs from the Spanner deletion-protection check, CKV_GCP_119, where a missing attribute passes).
- **PASS** only when `deletion_protection` is explicitly `true`.

## Non-compliant example
```hcl
resource "google_bigquery_table" "auth0_logs_external" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "auth0_logs_external"

  external_data_configuration {
    autodetect    = true
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://my-bucket/auth0-logs/*.json"]
  }
  # deletion_protection not set - defaults to false, table can be silently destroyed
}
```

## Remediated example
```hcl
resource "google_bigquery_table" "auth0_logs_external" {
  dataset_id = google_bigquery_dataset.logs.dataset_id
  table_id   = "auth0_logs_external"

  external_data_configuration {
    autodetect    = true
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://my-bucket/auth0-logs/*.json"]
  }

  deletion_protection = true  # <-- added
}
```

## Remediation steps
1. Add `deletion_protection = true` to every `google_bigquery_table` resource that holds data you cannot trivially recreate.
2. For genuinely disposable/ephemeral tables (e.g. transient staging tables recreated on every pipeline run), it's acceptable to leave this `false`, but isolate such tables in clearly-named modules to avoid the setting bleeding into production tables via copy-paste.
3. To intentionally delete a protected table, first apply a change setting `deletion_protection = false`, then remove the resource — this two-step process is auditable via your Terraform change history/PR review.
4. Requires a Google provider version that supports `deletion_protection` on `google_bigquery_table`; verify your `required_providers` version constraint.
5. Combine with BigQuery dataset-level protections (e.g. IAM restrictions on `bigquery.tables.delete`) for defense in depth, since deletion_protection only guards against Terraform-driven removal, not direct API/console deletion by a privileged user.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigQueryTableDeletionProtection.py)
- [Terraform `google_bigquery_table` resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigquery_table)
