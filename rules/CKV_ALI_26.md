# CKV_ALI_26: Ensure Kubernetes installs plugin Terway or Flannel to support standard policies
## Severity
**LOW** (score: 2.0/10)

Without Terway or Flannel as the CNI plugin, the Kubernetes cluster cannot enforce standard NetworkPolicy resources, leaving pod-to-pod traffic unsegmented and easing lateral movement if one workload is compromised.

## Summary
This check verifies that an Alibaba Cloud Container Service for Kubernetes (ACK) cluster is configured with a CNI network plugin — Terway (`terway-eniip`) or Flannel — that supports standard Kubernetes NetworkPolicy enforcement, correctly wired to a pod network (via `pod_vswitch_ids` or `pod_cidr`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_cs_kubernetes`

## Why it matters
Kubernetes `NetworkPolicy` objects are the primary mechanism for micro-segmenting pod-to-pod traffic inside a cluster (e.g., restricting a frontend namespace from reaching a payments database namespace directly). Not every CNI plugin implements `NetworkPolicy` enforcement — if the cluster's networking layer doesn't support it, any `NetworkPolicy` resources applied by application teams are silently ignored, giving a false sense of isolation while every pod can actually reach every other pod on the flat pod network. Terway and Flannel are two ACK-supported plugins capable of enforcing these policies (when correctly configured), so this check ensures the cluster's foundational network layer can actually honor the segmentation controls teams may rely on.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on `alicloud_cs_kubernetes`:
1. Requires either `pod_vswitch_ids` or `pod_cidr` to be set at all — otherwise FAIL immediately (no pod network configured).
2. Requires an `addons` block list; if missing, FAIL.
3. Extracts addon `name` values. If `"terway-eniip"` is present:
   - Requires `pod_vswitch_ids` to be set.
   - If `worker_vswitch_ids` and `master_vswitch_ids` are also set, FAILS if any pod vswitch ID overlaps with the worker or master vswitch IDs (pod network must use dedicated, non-overlapping vswitches/availability zones per Alibaba Cloud Terway requirements).
   - Otherwise PASSES.
4. If `"flannel"` is present instead, PASSES only if `pod_cidr` is set (Flannel requires an explicit pod CIDR).
5. If neither `terway-eniip` nor `flannel` addon is present, FAILS.

## Non-compliant example
```hcl
resource "alicloud_cs_kubernetes" "example" {
  name               = "example-cluster"
  worker_vswitch_ids = ["vsw-worker-1"]
  master_vswitch_ids = ["vsw-master-1"]
  # no pod_cidr and no pod_vswitch_ids configured
  # no addons block specifying terway-eniip or flannel
}
```

## Remediated example
```hcl
resource "alicloud_cs_kubernetes" "example" {
  name               = "example-cluster"
  worker_vswitch_ids = ["vsw-worker-1"]
  master_vswitch_ids = ["vsw-master-1"]
  pod_vswitch_ids    = ["vsw-pod-1"]   # <-- dedicated pod vswitch, distinct from worker/master

  addons {
    name = "terway-eniip"              # <-- fix: enables standard NetworkPolicy support
  }
}
```

## Remediation steps
1. Add an `addons` block specifying either `terway-eniip` or `flannel` as the cluster's CNI.
2. If using Terway: provision dedicated `pod_vswitch_ids` in the same availability zones as your worker/master vswitches, but using distinct vswitch resources (do not reuse worker/master vswitch IDs for pods).
3. If using Flannel: set `pod_cidr` to a CIDR block that does not overlap with your VPC or service CIDR.
4. Note this typically must be decided at cluster creation time — changing the CNI plugin on an existing running cluster is often not supported in-place and may require cluster recreation; plan accordingly.
5. After deploying, verify NetworkPolicy enforcement works as expected with a test policy before relying on it for isolation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/K8sEnableNetworkPolicies.py)
- [Alibaba Cloud ACK Terway networking guide](https://www.alibabacloud.com/help/en/container-service-for-kubernetes/latest/work-with-terway)
- [Alibaba Cloud `alicloud_cs_kubernetes` resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/cs_kubernetes)
