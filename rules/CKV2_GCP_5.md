# CKV2_GCP_5: Ensure that Cloud Audit Logging is configured properly across all services and all users from a project

## Severity
**LOW** (score: 2.0/10)

Exempting members from audit logging for allServices creates a blind spot that lets some principals act without a security audit trail, seriously hampering detection and investigation of malicious activity.

## Summary
This check ensures that a GCP project has an audit log config (`google_project_iam_audit_config`) applying to `allServices`, with no exempted members, so that Admin Activity, Data Access, and System Event logs are captured for every user and every service in the project without carve-outs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_project`, `google_project_iam_audit_config`

This is a graph-based check (Checkov "graph check", defined as JSON) that inspects the connection between a project and its audit config resource, rather than a single-resource Python check.

## Why it matters
Cloud Audit Logs are the authoritative record of who did what, when, and from where within a GCP project — critical for detecting privilege abuse, investigating breaches, and satisfying compliance mandates. Data Access audit logs (which record reads/writes to user data by GCP services like BigQuery, Storage, and Cloud SQL) are disabled by default and can additionally be configured with `exempted_members`, which suppresses log entries for specific principals. If a project's audit config does not cover `allServices`, or if it exempts certain members, then activity by those services or accounts goes unlogged. An attacker who compromises an exempted service account, or who operates against an unmonitored service, can act without leaving a forensic trail — completely defeating the purpose of audit logging.

## How Checkov evaluates this
The check filters for `google_project` resources and requires:
1. A `google_project_iam_audit_config` resource **exists** and is connected to the `google_project`.
2. On that audit config resource, `audit_log_config.*.exempted_members` must either **not exist** or be **empty** (no principals are carved out of logging).
3. The audit config's `service` attribute must equal `"allServices"` exactly (not a single named service like `storage.googleapis.com`), meaning the config applies project-wide across all services.

The check **fails** if the project has no audit config connected to it, if the config only targets a specific service instead of `allServices`, or if any members are exempted from logging.

## Non-compliant example
```hcl
resource "google_project" "delivery_platform_project" {
  name       = "delivery-platform"
  project_id = "delivery-platform-prod"
  org_id     = "123456789012"
}

resource "google_project_iam_audit_config" "audit" {
  project = google_project.delivery_platform_project.project_id
  service = "storage.googleapis.com"  # not "allServices"

  audit_log_config {
    log_type         = "DATA_READ"
    exempted_members = ["user:admin@example.com"]  # carve-out defeats logging
  }
}
```

## Remediated example
```hcl
resource "google_project" "delivery_platform_project" {
  name       = "delivery-platform"
  project_id = "delivery-platform-prod"
  org_id     = "123456789012"
}

resource "google_project_iam_audit_config" "audit" {
  project = google_project.delivery_platform_project.project_id
  service = "allServices"

  audit_log_config {
    log_type = "DATA_READ"
    # no exempted_members block - no one is carved out
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}
```

## Remediation steps
1. Add (or fix) a `google_project_iam_audit_config` resource for the affected project (`delivery_platform_project`), setting `service = "allServices"`.
2. Include `audit_log_config` blocks for `ADMIN_READ`, `DATA_READ`, and `DATA_WRITE` log types as appropriate for your compliance requirements — omitting a log type is different from exempting members, but for full coverage include all three.
3. Remove any `exempted_members` entries, or justify and document any exemption via an org-level policy exception rather than leaving it in Terraform.
4. Re-apply Terraform to `src/cloud/infra/terraform/delivery-platform/modules/delivery_platform/main.tf` and verify with `gcloud projects get-iam-policy <project_id>` that the audit config is present.
5. Be aware that enabling Data Access logs (especially `DATA_READ`) can significantly increase Cloud Logging volume and cost — budget accordingly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPAuditLogsConfiguredForAllServicesAndUsers.json
- Google Cloud docs: https://cloud.google.com/logging/docs/audit/configure-data-access
