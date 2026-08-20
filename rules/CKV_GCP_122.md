# CKV_GCP_122: Ensure Big Table Instances have deletion protection enabled

## Severity
**MEDIUM** (score: 5.0/10)

Missing deletion protection on a Bigtable instance is primarily an availability/data-loss concern (accidental or malicious removal of the instance and its data) rather than a direct access-control failure.

## Summary
This check requires `google_bigtable_instance` resources to explicitly set `deletion_protection = true`, so that Terraform will refuse to delete the Bigtable instance (and the data stored in it) without an explicit, separate change.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_bigtable_instance`
- **Check type:** resource (value check)

## Why it matters
Cloud Bigtable is a NoSQL wide-column store frequently used for high-throughput, low-latency workloads such as time-series data, IoT telemetry, ad-tech, and real-time analytics — often holding large volumes of data that would be costly or impossible to regenerate. Because Terraform operates declaratively, an accidental resource removal (bad refactor, incorrect module input causing a resource replacement, human error in a PR, or a wide-reaching `terraform destroy`) can delete the instance and irrecoverably lose its data (Bigtable does not have a native "trash"/undelete for deleted instances). Requiring `deletion_protection = true` forces a deliberate, reviewable step before the instance can actually be destroyed, protecting against both accidental and unauthorized destructive changes.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `deletion_protection`
- **Expected value:** `true`
- **`missing_block_result`** is explicitly set to `CheckResult.FAILED` — if the attribute is not set at all, the instance is treated as unprotected and the check **FAILS**.
- **PASS** only when `deletion_protection` is explicitly `true`.

## Non-compliant example
```hcl
resource "google_bigtable_instance" "telemetry" {
  name = "telemetry-instance"

  cluster {
    cluster_id   = "telemetry-cluster"
    zone         = "us-central1-b"
    num_nodes    = 3
    storage_type = "SSD"
  }
  # deletion_protection not set - defaults to false
}
```

## Remediated example
```hcl
resource "google_bigtable_instance" "telemetry" {
  name = "telemetry-instance"

  cluster {
    cluster_id   = "telemetry-cluster"
    zone         = "us-central1-b"
    num_nodes    = 3
    storage_type = "SSD"
  }

  deletion_protection = true  # <-- added
}
```

## Remediation steps
1. Add `deletion_protection = true` to every production `google_bigtable_instance` resource.
2. For genuinely ephemeral instances (e.g. short-lived load-test environments), it's acceptable to leave this `false`, but scope such instances to clearly-separated non-production modules/workspaces.
3. To intentionally delete a protected instance, first apply a change disabling `deletion_protection`, then remove the resource — keeping the two steps separate creates an auditable trail.
4. Requires a Google provider version that supports `deletion_protection` on `google_bigtable_instance`; verify your `required_providers` constraint.
5. Note this only protects against Terraform-driven and API-driven deletion attempts gated by this flag — pair with IAM restrictions on `bigtable.instances.delete` for defense in depth against direct console/API deletion by an overly-privileged principal.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigTableInstanceDeletionProtection.py)
- [Terraform `google_bigtable_instance` resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/bigtable_instance)
