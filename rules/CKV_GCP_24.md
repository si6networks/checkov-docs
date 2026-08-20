# CKV_GCP_24: Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters
## Severity
**LOW** (score: 2.0/10)

Disabling PodSecurityPolicy removes an admission-control layer that restricts privileged pods and host-level access, raising the risk of container breakout or privilege escalation within the cluster, though additional preconditions are needed for exploitation.

## Summary
This check fails when a `google_container_cluster` with `min_master_version` below 1.25 does not explicitly enable the `pod_security_policy_config` (PodSecurityPolicy admission controller).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`
- **Check type:** resource

## Why it matters
PodSecurityPolicy (PSP) was the original Kubernetes admission controller for restricting what a Pod spec is allowed to request — preventing privileged containers, host-network/host-PID access, host path mounts, running as root, unrestricted capabilities, etc. Without it enabled, any user or service account with permission to create Pods can request maximally privileged containers (e.g., `privileged: true`, hostPath mounts to `/`), which can be used to escape the container and compromise the underlying node or cluster. This is a legacy check: **PodSecurityPolicy was deprecated in Kubernetes 1.21 and removed entirely in 1.25**, replaced by Pod Security Admission (PSA) / Pod Security Standards. That's why the check only applies to clusters pinned below 1.25 — for 1.25+ clusters it is a no-op (`UNKNOWN`), since the feature doesn't exist anymore and the equivalent control is Pod Security Admission labels or policy engines like Gatekeeper/Kyverno.

## How Checkov evaluates this
The check parses `min_master_version`:
- If it can't parse a `major.minor` version, or the version is `>= 1.25`, the check returns `UNKNOWN`.
- If version `< 1.25`:
  - **PASS** — `pod_security_policy_config[0].enabled` is truthy.
  - **FAIL** — `pod_security_policy_config` is absent, or `enabled` is falsy/missing.
- If `min_master_version` is not set at all in config, the check returns `UNKNOWN`.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name               = "legacy-cluster"
  location           = "us-central1"
  min_master_version = "1.20"
  # no pod_security_policy_config -> FAILS
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name               = "legacy-cluster"
  location           = "us-central1"
  min_master_version = "1.20"

  pod_security_policy_config {
    enabled = true
  }
}
```

## Remediation steps
1. If the cluster is still on Kubernetes < 1.25, set `pod_security_policy_config { enabled = true }` and define appropriate `PodSecurityPolicy` objects restricting privileged workloads.
2. Strongly prefer instead **upgrading to GKE 1.25+ and migrating to Pod Security Admission** (namespace labels like `pod-security.kubernetes.io/enforce: restricted`) or a policy engine (Gatekeeper/Kyverno/OPA), since PSP is fully removed upstream and receives no further updates.
3. Migrating from PSP to PSA/Gatekeeper requires mapping your existing PSPs to equivalent policies before removing PSP — test thoroughly in non-prod, as Pods that violate the new policy will fail to schedule.
4. This check will simply stop applying once you upgrade past 1.25; treat it as a signal to plan the PSP-to-PSA migration, not something to satisfy indefinitely on old clusters.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEPodSecurityPolicyEnabled.py
- Kubernetes docs: https://kubernetes.io/docs/concepts/security/pod-security-standards/
