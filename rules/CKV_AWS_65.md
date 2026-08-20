# CKV_AWS_65: Ensure container insights are enabled on ECS cluster
## Severity
**LOW** (score: 2.0/10)

Container Insights is an observability/monitoring feature for ECS; its absence reduces operational visibility into cluster health but does not itself create an exploitable security weakness.

## Summary
This check verifies that an ECS cluster has the `containerInsights` cluster setting enabled (value `enabled` or `enhanced`), so that CloudWatch Container Insights collects detailed performance and resource-utilization metrics/logs for the cluster's tasks and services.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::ECS::Cluster`, property `Properties/ClusterSettings` (a list of `{Name, Value}` pairs).
- **Terraform**: `aws_ecs_cluster` resource, `setting { name = "containerInsights", value = ... }` block.

## Why it matters
Container Insights provides CPU, memory, disk, and network utilization metrics at the cluster, service, and task level, along with diagnostic logs — visibility that is otherwise largely absent from ECS by default. Without it, operators and security teams lack the observability needed to detect anomalous resource consumption (e.g., a compromised container cryptomining or exfiltrating data via unusual network throughput), to right-size tasks, or to diagnose availability incidents quickly. From a security/reliability standpoint, the absence of monitoring is itself a risk: an attacker who compromises a container can operate with far less chance of detection if there's no baseline metrics/alerting in place, and incident responders lose a key forensic data source (container-level resource and log correlation) during investigation.

## How Checkov evaluates this
**CloudFormation** (custom `BaseResourceCheck`): reads `Properties/ClusterSettings` (a list). For each setting entry, if `Name == "containerInsights"` and `Value` is `"enhanced"` or `"enabled"` → PASS. If no matching enabled setting is found (including when `ClusterSettings` is absent) → FAIL.

**Terraform** (custom `BaseResourceCheck`): reads the `setting` block list. For each entry where `name == ["containerInsights"]`, checks its `value` (unwrapping from a list if needed); PASSES if the value is `"enabled"` or `"enhanced"`, otherwise FAILS. If no `setting` block exists at all → FAIL.

Both fail-closed: an ECS cluster with no cluster settings configured at all does **not** pass by default, since Container Insights is off by default for new clusters unless explicitly enabled.

## Non-compliant example
```hcl
resource "aws_ecs_cluster" "app" {
  name = "app-cluster"
  # no setting block -> containerInsights defaults to disabled
}
```

## Remediated example
```hcl
resource "aws_ecs_cluster" "app" {
  name = "app-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"          # fixed (or "enhanced" for enhanced observability)
  }
}
```

## Remediation steps
1. Add a `setting { name = "containerInsights", value = "enabled" }` block to the `aws_ecs_cluster` resource (or the equivalent `ClusterSettings` entry in CloudFormation).
2. Consider `"enhanced"` instead of `"enabled"` for Container Insights with Enhanced Observability, which provides more granular, task/container-level metrics (available in newer ECS/provider versions).
3. Be aware Container Insights incurs additional CloudWatch charges (metrics and log ingestion) — budget accordingly, especially for large clusters.
4. This is a non-disruptive, in-place setting change and can be applied to running clusters without downtime.
5. Pair with CloudWatch Alarms on key Container Insights metrics (CPU/memory utilization, task count) to get proactive alerting value from the enabled data.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECSClusterContainerInsights.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSClusterContainerInsights.py)
- [AWS: Monitor Amazon ECS containers using Container Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html)
