# CKV_GCP_100: Ensure that BigQuery Tables are not anonymously or publicly accessible

## Severity
**CRITICAL** (score: 9.0/10)

Granting allUsers/allAuthenticatedUsers on a BigQuery table exposes potentially sensitive analytical data to the entire internet with no authentication required.

## Summary
This check ensures that IAM bindings/members applied to a BigQuery table do not grant access to the special public principals `allUsers` or `allAuthenticatedUsers`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource types**: `google_bigquery_table_iam_member`, `google_bigquery_table_iam_binding`

## Why it matters
BigQuery tables frequently hold sensitive analytical data — customer records, financial data, logs, PII. Granting `allUsers` means literally anyone on the internet, without any Google account, can access the table if the role permits (e.g., `roles/bigquery.dataViewer`); `allAuthenticatedUsers` means any person with any Google account whatsoever (not limited to your organization) gains access. Concretely:

- **Unauthenticated data exfiltration**: With `allUsers` bound to a viewer/reader role, an attacker needs no credentials at all to query or export table data — they only need to know (or discover, e.g., via a leaked project ID) the resource identifier.
- **Massive over-scoping with `allAuthenticatedUsers`**: This principal includes every Google Workspace/Gmail account holder globally, not just users within your organization — it is frequently misunderstood as "anyone in my org" when it actually means "anyone with a Google identity."
- **Regulatory exposure**: Publicly accessible tables containing regulated data (PII, PCI, PHI) can trigger data-breach notification obligations even if no confirmed exfiltration occurred, since the access control itself failed.
- **Silent, persistent exposure**: IAM bindings on a table don't expire and aren't obviously visible in day-to-day console navigation, so a mistaken public grant (e.g., copy-pasted from a public dataset example) can persist undetected for a long time.

## How Checkov evaluates this
The check (`BigQueryPrivateTable`) branches on the specific resource type:
- For **`google_bigquery_table_iam_member`**: reads the single `member` attribute; **FAILS** if it equals `"allUsers"` or `"allAuthenticatedUsers"`.
- For **`google_bigquery_table_iam_binding`**: reads the `members` list; **FAILS** if `allUsers` or `allAuthenticatedUsers` appears anywhere in that list.
- Otherwise **PASSES**. If neither `member` nor `members` is present in the config, the check returns no explicit result.

## Non-compliant example
```hcl
resource "google_bigquery_table_iam_member" "public_reader" {
  project    = "my-project"
  dataset_id = "analytics"
  table_id   = "customer_events"
  role       = "roles/bigquery.dataViewer"
  member     = "allUsers"
}
```

## Remediated example
```hcl
resource "google_bigquery_table_iam_member" "analyst_reader" {
  project    = "my-project"
  dataset_id = "analytics"
  table_id   = "customer_events"
  role       = "roles/bigquery.dataViewer"
  member     = "group:data-analysts@example.com"
}
```

## Remediation steps
1. Search for any `google_bigquery_table_iam_member`/`_iam_binding` resource with `member`/`members` set to `allUsers` or `allAuthenticatedUsers` and remove those bindings.
2. Replace with specific principals: `user:`, `group:`, or `serviceAccount:` bound to the minimum role actually required (prefer `roles/bigquery.dataViewer` over broader roles).
3. If public/anonymous access to a specific dataset is genuinely intended (e.g., a public open-data table), make that an explicit, reviewed exception rather than an accidental grant, and consider isolating that table in its own dataset/project so the exposure is contained and auditable.
4. Audit dataset-level (`google_bigquery_dataset_iam_*`) and project-level IAM bindings too, since a table can also become effectively public through inherited bindings even if the table-level binding itself looks fine.
5. Re-scan with Checkov and cross-check with Cloud Asset Inventory or IAM Recommender for any remaining public bindings not managed in this Terraform config (e.g., applied manually via console).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigQueryPrivateTable.py
- GCP BigQuery access control documentation: https://cloud.google.com/bigquery/docs/access-control
