# CKV_GCP_86: Ensure Cloud build workers are private
## Severity
**HIGH** (score: 7.0/10)

A Cloud Build worker pool with a public IP exposes CI/CD build infrastructure directly to the internet, broadening the attack surface for compromising build pipelines and their credentials/artifacts.

## Summary
This check requires `google_cloudbuild_worker_pool` resources to set `worker_config.no_external_ip = true`, so that Cloud Build private-pool workers do not receive a public IP address.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_cloudbuild_worker_pool`
- **Check type:** resource (attribute-value check on the nested `worker_config` block)

## Why it matters
Cloud Build workers execute your build pipeline — checking out source, running arbitrary build scripts, pulling dependencies, and often holding credentials/service-account tokens with access to source repos, artifact registries, and deployment targets. A worker with a public IP is directly reachable from (and can directly reach) the public internet without going through your VPC's network controls (firewall rules, Cloud NAT logging, private-access boundaries), which expands the attack surface for a compromised build step (e.g., a malicious dependency or a supply-chain-poisoned build script) to exfiltrate data or pivot outward, and makes the worker itself a more attractive target for direct inbound scanning/attack during the build. Keeping build workers private and routed only through your VPC (with Cloud NAT/Private Google Access for necessary egress) lets you apply the same network segmentation, logging, and egress controls you apply to other sensitive infrastructure.

## How Checkov evaluates this
The check (`CloudBuildWorkersArePrivate`, a `BaseResourceValueCheck`) inspects the attribute path `worker_config/[0]/no_external_ip` on `google_cloudbuild_worker_pool`.
- **PASS**: `no_external_ip` is set to `true` in the `worker_config` block.
- **FAIL**: `no_external_ip` is absent, or explicitly set to `false`.

## Non-compliant example
```hcl
resource "google_cloudbuild_worker_pool" "pool" {
  name     = "private-pool"
  location = "us-central1"

  worker_config {
    disk_size_gb   = 100
    machine_type   = "e2-standard-4"
    no_external_ip = false
  }
}
```

## Remediated example
```hcl
resource "google_cloudbuild_worker_pool" "pool" {
  name     = "private-pool"
  location = "us-central1"

  worker_config {
    disk_size_gb   = 100
    machine_type   = "e2-standard-4"
    no_external_ip = true
  }

  network_config {
    peered_network = google_compute_network.build_vpc.id
  }
}
```

## Remediation steps
1. Set `worker_config.no_external_ip = true` on the `google_cloudbuild_worker_pool` resource.
2. Add a `network_config` block pointing to a VPC (via VPC peering) so workers still have the network path they need — a private worker with no VPC peering and no NAT will be unable to reach external dependency registries.
3. Configure Cloud NAT or Private Google Access in the peered VPC for outbound access to package registries/APIs the build needs.
4. Verify any existing builds don't depend on inbound connectivity to the worker's public IP (rare, but check custom build steps/webhooks).
5. This is typically a non-disruptive, in-place update, but re-verify build connectivity after applying since network paths change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudBuildWorkersArePrivate.py
- GCP docs: https://cloud.google.com/build/docs/private-pools/private-pools-overview
