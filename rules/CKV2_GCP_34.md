# CKV2_GCP_34: Ensure Vertex AI index endpoint is private
## Severity
**MEDIUM** (score: 5.0/10)

Enabling a public endpoint on a Vertex AI index endpoint exposes vector-search/matching infrastructure to the internet, broadening the attack surface for a service that may hold or reveal sensitive embedded data.

## Summary
This check ensures that a Vertex AI Index Endpoint (used for vector similarity search / matching engine deployments) is not publicly accessible, i.e., `public_endpoint_enabled` is not set to `true`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_vertex_ai_index_endpoint`

## Why it matters
Vertex AI Index Endpoints serve vector similarity search (nearest-neighbor) queries, commonly used in recommendation systems, semantic search, and retrieval-augmented generation (RAG) pipelines. The underlying vector index is often built directly from proprietary or sensitive source content (documents, user embeddings, product catalogs) — querying it can leak information about that source data even without direct access to the raw records (e.g., via similarity-based inference or embedding inversion techniques). Exposing the index endpoint publicly allows unauthenticated or unauthorized parties to query the index, extract information about the indexed content, and abuse compute resources through unmetered queries. Requiring the endpoint to stay private forces all queries through a VPC-scoped network boundary, adding a critical layer of access control.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_vertex_ai_index_endpoint`:
- **PASS** if `public_endpoint_enabled` is absent or **not** equal to `true` (i.e., `false` or unset).
- **FAIL** if `public_endpoint_enabled` is explicitly set to `true`.

## Non-compliant example
```hcl
resource "google_vertex_ai_index_endpoint" "index_endpoint" {
  display_name = "product-similarity-index"
  region       = "us-central1"
  public_endpoint_enabled = true
}
```

## Remediated example
```hcl
resource "google_vertex_ai_index_endpoint" "index_endpoint" {
  display_name           = "product-similarity-index"
  region                  = "us-central1"
  public_endpoint_enabled = false
  network                 = "projects/my-project/global/networks/my-vpc"
}
```

## Remediation steps
1. Remove `public_endpoint_enabled = true` or explicitly set it to `false` on the `google_vertex_ai_index_endpoint` resource.
2. Configure VPC Network Peering with the Vertex AI managed services network and set the `network` attribute so the index endpoint is reachable only from within your private network.
3. Update client applications querying the index to use the private IP/internal endpoint path.
4. Switching between public and private endpoint modes typically requires recreating the index endpoint (this setting is generally immutable post-creation) — plan for redeployment of the deployed index.
5. Confirm firewall rules permit the internal services/applications that legitimately need to query the index.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPVertexAIPrivateIndexEndpoint.json
- GCP docs: https://cloud.google.com/vertex-ai/docs/vector-search/setup/setup
