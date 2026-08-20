# CKV_GCP_70: Ensure the GKE Release Channel is set
## Severity
**LOW** (score: 2.0/10)

Not enrolling in a release channel is a patch-management hygiene gap that increases the odds of running an unpatched, CVE-exposed Kubernetes version, but is not itself directly exploitable.

## Summary
This check ensures GKE clusters are enrolled in a release channel (Rapid, Regular, or Stable) so Google manages automatic version upgrades on a defined cadence, rather than the cluster running on an unmanaged, static Kubernetes version.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_container_cluster`

## Why it matters
Clusters not enrolled in a release channel are managed manually — the operator alone is responsible for tracking Kubernetes and node OS security patches and scheduling upgrades. In practice, unmanaged clusters routinely fall behind, leaving them exposed to known, patched Kubernetes CVEs (privilege escalation in the API server, kubelet vulnerabilities, container runtime escapes, etc.) for extended periods. Release channels give Google responsibility for rolling out validated patch versions automatically within a channel's cadence and support window, and also guarantee the cluster stays within Google's supported version skew — reducing both the "we forgot to patch" risk and the risk of running an end-of-life, unsupported Kubernetes minor version with no security backports at all.

## How Checkov evaluates this
Checkov inspects `release_channel[0].channel` on the `google_container_cluster` resource. Any value at all (`ANY_VALUE` — e.g. `"RAPID"`, `"REGULAR"`, or `"STABLE"`) causes a PASS. If the `release_channel` block is absent or the `channel` key is not set, the check FAILS.

## Non-compliant example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  # release_channel not configured -> static, unmanaged version
}
```

## Remediated example
```hcl
resource "google_container_cluster" "primary" {
  name     = "prod-cluster"
  location = "us-central1"

  release_channel {
    channel = "REGULAR"
  }
}
```

## Remediation steps
1. Add a `release_channel` block to every `google_container_cluster` resource.
2. Choose an appropriate channel: `RAPID` for early access to new versions, `REGULAR` for a balanced default (recommended for most production workloads), or `STABLE` for maximum stability/slowest cadence.
3. If the cluster currently pins `min_master_version`/`node_version` explicitly, remove or reconcile that with the chosen channel, since the channel will control upgrades going forward.
4. Note: moving an existing cluster into a release channel can trigger an upgrade to the channel's default version at apply time — review the target version and plan a maintenance window if needed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GKEReleaseChannel.py)
- [Google Cloud: About release channels](https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels)
