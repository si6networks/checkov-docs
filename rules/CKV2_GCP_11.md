# CKV2_GCP_11: Ensure GCP GCR Container Vulnerability Scanning is enabled
## Severity
**LOW** (score: 2.0/10)

Disabled Container Vulnerability Scanning on GCR removes a detective control for known CVEs in deployed images, increasing the chance that vulnerable software ships to production undetected, though it does not itself create an exploitable exposure.

## Summary
This check ensures that the Container Scanning API (`containerscanning.googleapis.com`) is enabled for the project, so images pushed to Google Container Registry / Artifact Registry are automatically scanned for known vulnerabilities.

## Applicability
Applies to Terraform, specifically the `google_project_services` resource (the resource used to enable Google Cloud APIs/services on a project).

## Why it matters
Without Container (Vulnerability) Scanning enabled, images pushed to GCR/Artifact Registry are never automatically checked against known-CVE databases. This means base-image or dependency vulnerabilities (e.g. an outdated OpenSSL, a vulnerable library with a known RCE) can sit undetected in production images indefinitely, since nothing in the pipeline surfaces them. This removes a low-cost, high-value safety net: vulnerability scanning is one of the cheapest ways to catch "known bad" software before or shortly after it reaches production, and its absence typically means vulnerable images are discovered only after an incident (or an external report) rather than proactively by CI/CD or registry-level tooling.

## How Checkov evaluates this
Single `attribute` condition on `google_project_services` resources: the `services` list attribute must `contains` the string `"containerscanning.googleapis.com"`. If that API is present in the enabled-services list, the check PASSes; if it's absent, the check FAILs.

## Non-compliant example
```hcl
resource "google_project_services" "project_apis" {
  project = "my-project"

  services = [
    "compute.googleapis.com",
    "container.googleapis.com",
    # containerscanning.googleapis.com is missing
  ]
}
```

## Remediated example
```hcl
resource "google_project_services" "project_apis" {
  project = "my-project"

  services = [
    "compute.googleapis.com",
    "container.googleapis.com",
    "containerscanning.googleapis.com",
  ]
}
```

## Remediation steps
1. Add `"containerscanning.googleapis.com"` to the `services` list of the project's `google_project_services` resource (or enable it directly via `gcloud services enable containerscanning.googleapis.com` / the Console if not managed in Terraform).
2. Confirm the Artifact Registry/Container Registry has vulnerability scanning triggered on push — this is automatic once the API is enabled for registries in the same project.
3. Wire scan results into your CI/CD pipeline (e.g. block deploys on critical/high severity findings) rather than relying on manual review.
4. Note this only enables the API; review IAM permissions (`roles/containeranalysis.*`) so relevant teams/pipelines can read scan results.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCRContainerVulnerabilityScanningEnabled.json
- GCP docs: https://cloud.google.com/artifact-analysis/docs/container-scanning-overview
