# CKV_GCP_21: Ensure Kubernetes Clusters are configured with Labels
## Severity
**LOW** (score: 2.0/10)

Missing labels on a GKE cluster is a resource-management and cost-attribution hygiene issue with no direct security exploitability.

## Summary
This check fails when a `google_container_cluster` resource does not set at least one key/value pair in `resource_labels`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
Labels are the primary mechanism GCP provides for cost allocation, ownership tracking, automated policy enforcement (e.g., org policies or IAM conditions keyed on labels), and inventory/asset management at scale. An unlabeled GKE cluster is harder to attribute to a team, environment, or cost center; during an incident, it slows down determining who owns the cluster and whether it's in scope for a security control (e.g., "all prod clusters must have X enabled"). While this is not a direct vulnerability, missing labels degrade operational security posture — you cannot reliably enforce or audit controls (backup, encryption tiering, network policy) across a fleet you cannot programmatically identify by label.

## How Checkov evaluates this
- **PASS** — `resource_labels` is set and is a dict with at least one key.
- **FAIL** — `resource_labels` is absent, or present but empty (`{}`).

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"
  # no resource_labels -> FAILS
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  resource_labels = {
    environment = "production"
    team        = "platform"
    cost-center = "eng-infra"
  }
}
```

## Remediation steps
1. Add a `resource_labels` map to every `google_container_cluster` with at least `environment`, `team`/`owner`, and a cost-center or project tag.
2. Standardize a labeling schema across the org (consider a shared Terraform variable/module default) so labels are consistent and queryable in Cloud Asset Inventory / BigQuery billing export.
3. Note GCP label keys/values must be lowercase, and match `^[a-z0-9_-]+$` — avoid uppercase or special characters.
4. This is a metadata-only change and does not require cluster replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEHasLabels.py
- GCP docs: https://cloud.google.com/resource-manager/docs/creating-managing-labels
