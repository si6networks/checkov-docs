# CKV_GCP_119: Ensure Spanner Database has deletion protection enabled

## Severity
**MEDIUM** (score: 5.0/10)

Missing deletion protection on a Spanner database is primarily an availability/data-loss risk from accidental or malicious deletion, not a confidentiality or access-control failure.

## Summary
This check requires `google_spanner_database` resources to set `deletion_protection = true`, preventing the database (and all data in it) from being deleted via `terraform destroy` or `terraform apply` operations that would remove the resource.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_spanner_database`
- **Check type:** resource (value check)

## Why it matters
Cloud Spanner is typically used for mission-critical, globally-distributed relational data (financial records, inventory, user data). Terraform's declarative model means that a mistaken resource rename, a bad refactor of the resource address, a `terraform destroy`, or an errant `-target` apply can delete a Spanner database instance along with all its data. `deletion_protection` is a safety attribute that causes Terraform (and the underlying GCP API) to refuse the deletion until it is explicitly disabled — providing a deliberate, auditable step before an irreversible, potentially catastrophic data-loss event.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `deletion_protection`
- **Expected value:** `true`
- **`missing_block_result`** is explicitly set to `CheckResult.PASSED` — meaning if the `deletion_protection` attribute is entirely absent from the config, Checkov treats it as a PASS (this reflects the GCP provider's own default value for this attribute being `true` in recent provider versions).
- **FAIL** only occurs if `deletion_protection` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "google_spanner_database" "orders_db" {
  instance = google_spanner_instance.main.name
  name     = "orders-db"
  ddl = [
    "CREATE TABLE orders (id INT64 NOT NULL) PRIMARY KEY(id)",
  ]

  deletion_protection = false
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

  deletion_protection = true  # <-- changed from false
}
```

## Remediation steps
1. Set `deletion_protection = true` explicitly on all production `google_spanner_database` resources (do not rely on defaults, since default behavior can vary by provider version and explicit intent is clearer for reviewers).
2. For genuinely ephemeral databases (e.g., in a throwaway test/CI environment), you may explicitly set `deletion_protection = false`, but isolate these to non-production modules/workspaces so the setting doesn't leak into production configs via copy-paste.
3. To actually delete a protected database when needed, first set `deletion_protection = false`, apply that change, and only then remove/destroy the resource — this creates an auditable two-step process.
4. Requires Google provider version that supports the `deletion_protection` attribute on `google_spanner_database` (added in relatively recent provider releases) — verify your `required_providers` version constraint.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/SpannerDatabaseDeletionProtection.py)
- [Terraform `google_spanner_database` resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/spanner_database)
