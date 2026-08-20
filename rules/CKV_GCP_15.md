# CKV_GCP_15: Ensure that BigQuery datasets are not anonymously or publicly accessible
## Severity
**CRITICAL** (score: 9.1/10)

A BigQuery dataset ACL granting access to allUsers or allAuthenticatedUsers exposes potentially sensitive analytical data to the entire internet or any Google account holder with no authentication boundary.

## Summary
This check fails when a `google_bigquery_dataset` grants access to `allUsers` or `allAuthenticatedUsers` in its `access` block, which would make the dataset readable by anyone on the internet (or any Google account holder), respectively.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_bigquery_dataset`
- **Check type:** resource

## Why it matters
BigQuery datasets frequently contain analytics on customer behavior, financial data, logs with PII, or other sensitive aggregated data. Granting the `special_group` values `allUsers` (literally anyone on the internet, unauthenticated) or `allAuthenticatedUsers` (any Google account in the world, not just your org) in an `access` entry turns the dataset into a public data leak. This is one of the most common and severe GCP misconfigurations — equivalent in impact to an open S3 bucket in AWS — and has caused real-world data breaches when datasets were shared broadly for "convenience" during development and never locked back down.

## How Checkov evaluates this
The check iterates every entry in the `access` list of the `google_bigquery_dataset` resource:

- **FAIL** — any `access` block has `special_group` equal to `["allAuthenticatedUsers"]` or `["allUsers"]`.
- **FAIL** — an `access` block exists that doesn't contain any of the recognized principal-type keys (`user_by_email`, `group_by_email`, `domain`, `view`, `routine`, `dataset`) — this catches the case where Terraform state shows only a bare `role` key, which happens when `allUsers`/`allAuthenticatedUsers` was added manually outside the expected schema shape.
- **PASS** — otherwise (no `access` block, or all entries scope to specific users/groups/domains/views/routines/other datasets).

## Non-compliant example
```hcl
resource "google_bigquery_dataset" "analytics" {
  dataset_id = "customer_analytics"
  location   = "US"

  access {
    role          = "READER"
    special_group = "allUsers"
  }

  access {
    role          = "OWNER"
    user_by_email = "data-team@example.com"
  }
}
```

## Remediated example
```hcl
resource "google_bigquery_dataset" "analytics" {
  dataset_id = "customer_analytics"
  location   = "US"

  access {
    role           = "READER"
    group_by_email = "analytics-readers@example.com"   # scoped, not public
  }

  access {
    role          = "OWNER"
    user_by_email = "data-team@example.com"
  }
}
```

## Remediation steps
1. Remove any `access` block whose `special_group` is `allUsers` or `allAuthenticatedUsers`.
2. Replace it with a scoped principal: `user_by_email`, `group_by_email`, `domain`, or a cross-dataset/view authorization (`view`/`dataset` block) for legitimate cross-project sharing.
3. If external sharing is genuinely required, use BigQuery's **Analytics Hub** or authorized views scoped to specific groups instead of `allUsers`.
4. Audit existing datasets outside Terraform too (`bq show --format=prettyjson` or the Cloud Console IAM tab) since this misconfiguration is often introduced via console clicks, not just IaC.
5. No downtime/replacement is needed — this is a metadata-only IAM change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleBigQueryDatasetPublicACL.py
- GCP docs: https://cloud.google.com/bigquery/docs/access-control
