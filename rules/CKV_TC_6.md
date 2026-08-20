# CKV_TC_6: Ensure Tencent Cloud TKE clusters enable log agent

## Severity
**MEDIUM** (score: 5.0/10)

A disabled Kubernetes cluster log agent removes audit/event visibility needed to detect and investigate malicious in-cluster activity, which is a genuine but detection-layer (not access-control) security gap.

## Summary
This check ensures that Tencent Kubernetes Engine (TKE) clusters have the built-in log agent enabled so that container/cluster logs are collected.

## Applicability
Terraform, resource type `tencentcloud_kubernetes_cluster` (Tencent Cloud provider).

## Why it matters
Without a log agent shipping container and cluster logs to a centralized store, security-relevant events inside a Kubernetes cluster — abnormal process execution, container escapes, unexpected privilege escalation, failed authentication attempts against the API server, or a compromised pod exfiltrating data — leave no durable trail once the pod or node is terminated or rescheduled. Kubernetes workloads are inherently ephemeral; logs kept only on a node's local disk or a pod's stdout buffer are lost the moment that pod is evicted, rescheduled, or the node is recycled, which is exactly the situation an attacker benefits from (evidence disappearing along with the compromised workload). Centralized logging via the TKE log agent is a prerequisite for any meaningful incident detection, forensic investigation, or compliance audit trail for workloads running in the cluster.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested `log_agent.enabled` attribute of a `tencentcloud_kubernetes_cluster` resource. Checkov expects this value to be `true`. If `log_agent` is absent, or `log_agent.enabled` is `false` or unset, the check **FAILS**; if `log_agent { enabled = true }` is configured, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_kubernetes_cluster" "example" {
  cluster_name    = "prod-cluster"
  vpc_id          = tencentcloud_vpc.app_vpc.id
  cluster_max_pod_num = 32
  # log_agent block omitted -> log agent disabled
}
```

## Remediated example
```hcl
resource "tencentcloud_kubernetes_cluster" "example" {
  cluster_name        = "prod-cluster"
  vpc_id              = tencentcloud_vpc.app_vpc.id
  cluster_max_pod_num = 32

  log_agent {
    enabled = true   # cluster log agent collects and ships container/cluster logs
  }
}
```

## Remediation steps
1. Add a `log_agent { enabled = true }` block to every `tencentcloud_kubernetes_cluster` resource.
2. Configure a log collection destination (e.g. Tencent Cloud Log Service / CLS topic) so collected logs land somewhere queryable and retained per your compliance requirements.
3. Ensure log retention and access controls on the destination log store meet your organization's audit and incident-response requirements.
4. For existing clusters, enabling the log agent is typically a non-disruptive update, but confirm cluster version/add-on compatibility before applying in production.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/TKELogAgentEnabled.py
