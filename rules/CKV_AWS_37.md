# CKV_AWS_37: Ensure Amazon EKS control plane logging is enabled for all log types

## Severity
**LOW** (score: 2.0/10)

Disabled control-plane and especially audit logging removes the primary forensic record of Kubernetes API activity and RBAC decisions, letting an attacker who compromises the cluster operate with substantially reduced risk of detection or post-incident attribution.

## Summary
This check ensures that an `aws_eks_cluster` resource enables all five EKS control-plane log types (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`) rather than a subset or none.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Check type:** resource check
- **Entities:** `aws_eks_cluster` (attribute `enabled_cluster_log_types`)

## Why it matters
By default, EKS control-plane logging is disabled — the Kubernetes API server, audit logs, authenticator, controller manager, and scheduler produce no logs shipped to CloudWatch unless explicitly enabled. This is a major blind spot for both security monitoring and operational troubleshooting:
- **`api`** logs capture all API server requests — essential for detecting reconnaissance, unauthorized resource access attempts, or abuse of the Kubernetes API.
- **`audit`** logs are the single most important source for forensic investigation of a cluster compromise — they record who did what, when, including RBAC decisions, and are commonly required for compliance (PCI-DSS, SOC 2, FedRAMP).
- **`authenticator`** logs capture IAM-to-Kubernetes-RBAC authentication events (via aws-iam-authenticator), critical for detecting unauthorized or unusual authentication patterns.
- **`controllerManager`** and **`scheduler`** logs help detect anomalous cluster behavior and are useful for both security and operational debugging.

Without all five enabled, an attacker who gains access to the cluster (e.g., via a compromised pod, leaked kubeconfig, or exploited RBAC misconfiguration) can operate with reduced risk of detection, and incident responders lose critical audit trail data needed to reconstruct what happened.

## How Checkov evaluates this
Custom logic in `scan_resource_conf`: it reads the `enabled_cluster_log_types` attribute and checks that **all** of `["api", "audit", "authenticator", "controllerManager", "scheduler"]` are present in the configured list (handling both flat string-list and nested-list HCL representations). If even one of the five log types is missing, or the attribute is unset entirely, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = var.subnet_ids
  }

  enabled_cluster_log_types = ["api", "audit"]
}
```

## Remediated example
```hcl
resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = var.subnet_ids
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
}
```

## Remediation steps
1. Set `enabled_cluster_log_types` to include all five values: `api`, `audit`, `authenticator`, `controllerManager`, `scheduler`.
2. Confirm the CloudWatch log group `/aws/eks/<cluster-name>/cluster` has an appropriate retention policy set (EKS creates it with indefinite retention by default, which can accrue cost).
3. This is a mutable cluster setting and does not require cluster replacement, but changes may take a few minutes to propagate.
4. Consider setting up CloudWatch metric filters or forwarding to a SIEM for real-time alerting on suspicious audit log entries (e.g., unusual `exec` calls, RBAC denials, or `secrets` access).
5. Be aware of the added CloudWatch Logs ingestion/storage cost, especially for `audit` logs on high-traffic clusters — budget accordingly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSControlPlaneLogging.py
- AWS docs: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
