# CKV_GCP_120: Ensure Spanner Database has drop protection enabled

## Severity
**HIGH** (score: 7.5/10)

Missing drop protection on a Spanner database creates an availability/data-loss exposure (accidental or malicious database deletion) rather than a direct confidentiality or access-control breach.

## Summary
This check requires `google_spanner_database` resources to explicitly set `enable_drop_protection = true`, so the database cannot be accidentally dropped through the Spanner API/console independent of Terraform's own deletion protection.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_spanner_database`
- **Check type:** resource (value check)

## Why it matters
`enable_drop_protection` is a GCP Spanner–native safeguard (distinct from Terraform's `deletion_protection`, which only governs Terraform-driven deletes). It prevents the database from being dropped directly via the Cloud Spanner API, `gcloud`, or the console — for example by an operator running an ad hoc `gcloud spanner databases delete` command, or another automation tool acting outside of Terraform entirely. Since Spanner typically holds critical, hard-to-recover relational data, having this protection enforced at the cloud-provider level (not just at the IaC tool level) closes a gap where someone with console/API access, but not Terraform access, could otherwise destroy the database.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `enable_drop_protection`
- **Expected value:** `true`
- **`missing_block_result`** is explicitly set to `CheckResult.FAILED` — unlike the related `deletion_protection` attribute (CKV_GCP_119), if `enable_drop_protection` is not set at all, the check treats this as a **FAIL** (the GCP API default for this attribute is `false`, so omitting it leaves the database unprotected).
- **PASS** only when `enable_drop_protection` is explicitly `true`.

## Non-compliant example
```hcl
resource "google_spanner_database" "orders_db" {
  instance = google_spanner_instance.main.name
  name     = "orders-db"
  ddl = [
    "CREATE TABLE orders (id INT64 NOT NULL) PRIMARY KEY(id)",
  ]
  # enable_drop_protection not set - defaults to false, database can be dropped via API/console
}
```

## Remediated example
```hcl
resource "google_spanner_database" "orders_db" {
  instance = google_spanner_instance.main.name
  name     = "orders-db"
  ddl = [
    "CREATE TABLE orders (id INT64 NOT NULL) PRIMARY KEY(id)",
  ]

  enable_drop_protection = true  # <-- added
}
```

## Remediation steps
1. Add `enable_drop_protection = true` to every production `google_spanner_database` resource.
2. Also set Terraform's own `deletion_protection = true` (see CKV_GCP_119) — the two attributes are complementary: one protects against Terraform-driven deletion, the other against direct API/console deletion.
3. To intentionally drop a protected database, first apply a change setting `enable_drop_protection = false`, then perform the drop — this creates a deliberate, auditable step.
4. Requires a Google provider version that supports `enable_drop_protection` on `google_spanner_database`; check your `required_providers` version constraints.
5. For non-production/ephemeral databases where frequent teardown is expected (e.g., CI test databases), it's acceptable to leave this `false`, but keep such resources isolated from production modules.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/SpannerDatabaseDropProtection.py)
- [Terraform `google_spanner_database` resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/spanner_database)
