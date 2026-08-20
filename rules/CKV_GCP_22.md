# CKV_GCP_22: Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image
## Severity
**LOW** (score: 2.0/10)

Using a non-Container-Optimized-OS node image increases the node's attack surface (larger OS footprint, weaker default hardening) versus GKE's minimal, security-hardened COS image, but does not by itself grant an attacker access.

## Summary
This check fails when a `google_container_node_pool` (on a cluster with `version` older than 1.24) does not use a Container-Optimized OS (`cos*`) image type for its nodes and doesn't remove the default node pool.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_node_pool`
- **Check type:** resource

## Why it matters
Container-Optimized OS (COS) is a hardened, minimal, Google-maintained OS purpose-built for running containers: it has a locked-down read-only root filesystem, a small attack surface (no package manager, minimal installed software), automatic OS-level security patching, and is tightly integrated with GKE's security features (like seccomp defaults). Using a general-purpose OS image (e.g., Ubuntu) for node images increases the attack surface (more installed packages, more potential CVEs, mutable filesystem) and shifts patching burden onto the operator. The check is explicitly a **legacy check**: since Docker/dockershim support was removed in Kubernetes 1.24+, clusters at that version or newer are treated as not applicable (`UNKNOWN`) because the underlying assumption about container-runtime-specific node images no longer strictly applies the same way.

## How Checkov evaluates this
For a node pool with an associated cluster `version`:
- If the major.minor version parses to `>= 1.24`, the check returns `UNKNOWN` (not applicable — dockershim/legacy runtime distinction is moot).
- If the version is `< 1.24` (or unparsable → `UNKNOWN`):
  - **PASS** — `node_config[0].image_type` starts with `cos` (case-insensitive), e.g. `COS`, `COS_CONTAINERD`.
  - **PASS** — `remove_default_node_pool` is truthy (the default node pool, which itself uses COS, is being removed in favor of a custom-managed pool — treated as compliant since the insecure default pool won't persist).
  - **FAIL** — otherwise (e.g., `image_type` is `UBUNTU` or `UBUNTU_CONTAINERD`, and the default pool isn't removed).
  - If `version` is absent from config entirely, the check returns `UNKNOWN`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name    = "legacy-cluster"
  version = "1.22"
}

resource "google_container_node_pool" "pool" {
  name    = "default-pool"
  cluster = google_container_cluster.primary.name
  version = "1.22"

  node_config {
    machine_type = "e2-medium"
    image_type   = "UBUNTU_CONTAINERD"   # not COS -> FAILS
  }
}
```

## Remediated example
```hcl
resource "google_container_node_pool" "pool" {
  name    = "default-pool"
  cluster = google_container_cluster.primary.name
  version = "1.22"

  node_config {
    machine_type = "e2-medium"
    image_type   = "COS_CONTAINERD"   # Container-Optimized OS -> PASSES
  }
}
```

## Remediation steps
1. Set `node_config.image_type` to `COS_CONTAINERD` (recommended) or `COS` on all node pools.
2. If you have a business reason to run a non-COS image, ensure it isn't the cluster's default node pool, or explicitly `remove_default_node_pool = true` and manage a separate custom pool.
3. Note that changing `image_type` on an existing node pool typically requires node pool recreation/rolling upgrade — plan for a maintenance window or use surge upgrades to avoid workload disruption.
4. Clusters on Kubernetes 1.24+ are exempt from this specific legacy check (dockershim removal changed the underlying rationale), but COS remains best practice regardless of version.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEUseCosImage.py
- GCP docs: https://cloud.google.com/container-optimized-os/docs
