# CKV2_GCP_33: Ensure Vertex AI endpoint is private
## Severity
**MEDIUM** (score: 5.0/10)

A Vertex AI endpoint that is not restricted to a private network can be reached over the public internet, exposing model inference/serving (and any sensitive inputs or outputs) to unauthenticated or broader network access than intended.

## Summary
This check ensures that a Vertex AI Endpoint resource is deployed into a VPC network (via the `network` attribute) rather than exposed as a public endpoint.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_endpoint`

## Why it matters
A Vertex AI Endpoint serves live predictions from deployed ML models, often invoked with business-sensitive input data (customer records, financial transaction details, images/documents) and returning proprietary model outputs. A public (internet-facing) endpoint is reachable by anyone who obtains or guesses its URL/API path, exposing it to unauthorized prediction requests (which can be a paid-resource abuse vector / denial-of-wallet attack), model extraction attempts (repeatedly querying to reverse-engineer model behavior), and potential injection of malicious inputs designed to trigger model failures or extract training data (model inversion attacks). Configuring the endpoint to use a private VPC network restricts access to only clients within the organization's network perimeter, layering network-level access control on top of any IAM/API-key authentication.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_vertex_ai_endpoint`:
- **PASS** if the `network` attribute exists (the endpoint is peered into a private VPC network).
- **FAIL** if `network` is absent (defaults to a publicly reachable endpoint).

## Non-compliant example
```hcl
resource "google_vertex_ai_endpoint" "endpoint" {
  name         = "my-endpoint"
  display_name = "prod-model-endpoint"
  location     = "us-central1"
  # no network -> public endpoint
}
```

## Remediated example
```hcl
resource "google_vertex_ai_endpoint" "endpoint" {
  name         = "my-endpoint"
  display_name = "prod-model-endpoint"
  location     = "us-central1"
  network      = "projects/my-project/global/networks/my-vpc"
}
```

## Remediation steps
1. Set up VPC Network Peering between your VPC and the Vertex AI managed services network (required prerequisite for private endpoints).
2. Set the `network` attribute on the `google_vertex_ai_endpoint` resource to the peered VPC's resource path.
3. Update client applications calling the endpoint to reach it via the private IP/internal DNS rather than the public API path.
4. The `network` attribute is set at endpoint creation time and cannot be changed afterward — converting an existing public endpoint to private requires creating a new endpoint and redeploying models to it.
5. Confirm firewall rules and IAM policies on the VPC still permit legitimate internal callers.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexAIPrivateEndpoint.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/general/vpc-peering
