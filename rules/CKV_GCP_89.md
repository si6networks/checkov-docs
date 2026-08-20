# CKV_GCP_89: Ensure Vertex AI instances are private
## Severity
**HIGH** (score: 7.0/10)

A Vertex AI notebook instance with a public IP exposes an interactive ML development environment (with access to data, credentials, and code execution) directly to the internet.

## Summary
This check requires `google_notebooks_instance` (Vertex AI Workbench / user-managed notebook) resources to set `no_public_ip = true`, so the notebook VM does not receive a public IP address.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_notebooks_instance`
- **Check type:** resource (attribute-value check)

## Why it matters
Vertex AI Workbench notebook instances run Jupyter with root-level access to a VM that often has service-account credentials scoped to read/write training data, models, and other GCP resources (BigQuery, Cloud Storage buckets, Vertex AI pipelines). A notebook instance with a public IP is directly reachable from the internet, making it a target for unauthorized access attempts against the Jupyter interface or the underlying SSH/VM surface — and if compromised, an attacker inherits whatever data-science/ML-pipeline access the attached service account has, which is frequently broad (training data can include sensitive/regulated inputs, and models/artifacts represent significant IP). Keeping notebooks private (VPC-only, reachable via Private Google Access, IAP tunneling, or a bastion) removes this direct internet attack surface and forces access through your network's existing authentication and logging controls.

## How Checkov evaluates this
The check (`VertexAIPrivateInstance`, a `BaseResourceValueCheck`) inspects the `no_public_ip` attribute on `google_notebooks_instance`, with expected value `true`. The code comment notes it explicitly "accounts for if key is present but is set to False."
- **PASS**: `no_public_ip = true`.
- **FAIL**: `no_public_ip` is absent or set to `false` (default behavior assigns a public IP).

## Non-compliant example
```hcl
resource "google_notebooks_instance" "ml_notebook" {
  name         = "ml-workbench"
  location     = "us-central1-a"
  machine_type = "n1-standard-4"

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }
  # no_public_ip not set -> instance gets a public IP
}
```

## Remediated example
```hcl
resource "google_notebooks_instance" "ml_notebook" {
  name         = "ml-workbench"
  location     = "us-central1-a"
  machine_type = "n1-standard-4"
  no_public_ip = true

  vm_image {
    project      = "deeplearning-platform-release"
    image_family = "tf-latest-cpu"
  }

  network = google_compute_network.ml_vpc.id
  subnet  = google_compute_subnetwork.ml_subnet.id
}
```

## Remediation steps
1. Set `no_public_ip = true` on the `google_notebooks_instance` resource.
2. Attach the instance to a VPC/subnet that has Private Google Access enabled so it can still reach Google APIs (Cloud Storage, BigQuery, Container Registry) without a public IP.
3. Provide access for data scientists via IAP TCP forwarding, a Cloud VPN/Interconnect connection, or a bastion host — direct public access will no longer work.
4. `no_public_ip` is typically set at creation time; changing it on an existing instance may require recreating the instance (check current provider behavior, and back up notebook contents/disks first).
5. Confirm any automation (CI notebooks execution, scheduled jobs) that assumed public reachability is updated to use the private network path.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/VertexAIPrivateInstance.py
- GCP docs: https://cloud.google.com/vertex-ai/docs/workbench/instances/manage-network
