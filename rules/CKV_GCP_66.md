# CKV_GCP_66: Ensure use of Binary Authorization
## Severity
**LOW** (score: 2.0/10)

Missing Binary Authorization removes a supply-chain gate that would otherwise block unvetted or malicious container images from running arbitrary code inside the cluster.

## Summary
This check ensures GKE clusters enforce Binary Authorization, a deploy-time control that only allows container images which have been signed/attested by a trusted authority to run on the cluster.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Without Binary Authorization, any image that can be pulled by the cluster's nodes (from a public registry, a compromised internal registry, or an image with a typo-squatted name) can be deployed and executed. This removes a key supply-chain security control: there is no automated gate ensuring only images that passed vulnerability scanning, code review, or CI/CD attestation actually reach production. An attacker who gains push access to a registry, or who tricks a pipeline into deploying an unvetted image, can run arbitrary code inside the cluster. Binary Authorization closes this gap by requiring cryptographic attestations before the API server will admit a Pod backed by a given image.

## How Checkov evaluates this
The check reads the `google_container_cluster` resource configuration and looks for enforcement across three historical provider API shapes:
- **Google provider ≥ v4.31.0:** `binary_authorization[0].evaluation_mode == "PROJECT_SINGLETON_POLICY_ENFORCE"` → PASS.
- **Google provider v4.29.0–v4.30.0:** `binary_authorization[0].evaluation_mode == true` → PASS.
- **Google provider ≤ v4.28.0:** top-level `enable_binary_authorization == true` → PASS.

If none of these conditions are met (attribute absent, or set to a disabling value such as `DISABLED`/`false`), the check FAILS.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  # binary_authorization block omitted entirely
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}
```

## Remediation steps
1. Enable the Binary Authorization API on the project (`binaryauthorization.googleapis.com`).
2. Add a `binary_authorization` block to the `google_container_cluster` resource with `evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"` (requires Google provider ≥ v4.31.0; use `evaluation_mode = true` for v4.29.0–v4.30.0, or `enable_binary_authorization = true` for older provider versions).
3. Define a project-level Binary Authorization policy (`google_binary_authorization_policy`) specifying required attestors, or a default admission rule.
4. Configure your CI/CD pipeline to attach attestations (signed by an approved attestor) to images after they pass required checks (vulnerability scan, tests, etc.).
5. Roll this out to a non-production cluster first — enforcing an empty/incorrect policy will block all deployments until images are properly attested.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEBinaryAuthorization.py)
- [Google Cloud: Binary Authorization overview](https://cloud.google.com/binary-authorization/docs/overview)
